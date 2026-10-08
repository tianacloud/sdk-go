package tiana

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestTLSVerification(t *testing.T) {
	cases := []struct {
		name, certificate, root string
		version                 uint16
		alpn                    []string
		ok                      bool
	}{
		{"wildcard", "wildcard", "wildcard", tls.VersionTLS13, []string{"h2"}, true},
		{"wrong_name", "wrong", "wrong", tls.VersionTLS13, []string{"h2"}, false},
		{"untrusted", "endpoint", "unrelated", tls.VersionTLS13, []string{"h2"}, false},
		{"tls12", "endpoint", "endpoint", tls.VersionTLS12, []string{"h2"}, false},
		{"missing_alpn", "endpoint", "endpoint", tls.VersionTLS13, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testTLS(t, tc.certificate)
			config.MinVersion = tc.version
			config.MaxVersion = tc.version
			config.NextProtos = tc.alpn
			s := listenTest(t, config, func(conn *tls.Conn) {
				p := newPeer(t, conn, 65535)
				if p == nil {
					return
				}
				for {
					f, err := p.fr.ReadFrame()
					if err != nil {
						return
					}
					if f, ok := f.(*http2.MetaHeadersFrame); ok {
						p.success(f.StreamID, values(f)["tiana-request-id"], false)
					}
				}
			})
			c := clientFor(t, s, func(cfg *Config) { cfg.RootCAs = testRoots(t, tc.root) })
			stream, err := c.Connect(context.Background(), HranaHTTP)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				stream.Close()
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != TLS || typed.Committed {
				t.Fatalf("TLS accepted or misclassified: %v", err)
			}
		})
	}
}

func TestPendingCancellationTimeoutAndNoReplay(t *testing.T) {
	for _, mode := range []string{"cancel", "response_timeout", "client_close"} {
		t.Run(mode, func(t *testing.T) {
			request := make(chan struct{}, 1)
			var count atomic.Int32
			s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
				p := newPeer(t, conn, 65535)
				if p == nil {
					return
				}
				for {
					f, err := p.fr.ReadFrame()
					if err != nil {
						return
					}
					switch f.(type) {
					case *http2.MetaHeadersFrame:
						count.Add(1)
						request <- struct{}{}
					case *http2.DataFrame:
						t.Error("pending tunnel sent DATA")
					}
				}
			})
			c := clientFor(t, s, func(cfg *Config) { cfg.ResponseTimeout = 50 * time.Millisecond })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := c.Connect(ctx, HranaHTTP); done <- err }()
			<-request
			if mode == "cancel" {
				cancel()
			}
			if mode == "client_close" {
				c.Close()
			}
			select {
			case err := <-done:
				var typed *Error
				if !errors.As(err, &typed) || typed.Committed {
					t.Fatalf("unexpected pending error: %v", err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if mode == "response_timeout" && typed.Kind != Timeout {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Connect remained blocked")
			}
			c.Close()
			if count.Load() != 1 {
				t.Fatal("CONNECT replayed")
			}
		})
	}
}

func TestRSTIsolationAndCommittedFailure(t *testing.T) {
	var requests atomic.Int32
	s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		p := newPeer(t, conn, 65535)
		if p == nil {
			return
		}
		for {
			f, err := p.fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				requests.Add(1)
				p.success(f.StreamID, values(f)["tiana-request-id"], false)
				if f.StreamID == 3 {
					p.fr.WriteRSTStream(1, http2.ErrCodeInternal)
					p.fr.WriteData(3, false, []byte("sibling"))
				}
			case *http2.DataFrame:
				if f.StreamID == 3 {
					p.fr.WriteData(3, f.StreamEnded(), f.Data())
				}
			}
		}
	})
	c := clientFor(t, s, nil)
	first := connectFor(t, c, context.Background())
	second := connectFor(t, c, context.Background())
	_, err := first.Read(make([]byte, 1))
	var typed *Error
	if !errors.As(err, &typed) || !typed.Committed || typed.Retryable() {
		t.Fatalf("incorrect reset: %v", err)
	}
	readExact(t, second, "sibling")
	if _, err := second.Write([]byte("still-live")); err != nil {
		t.Fatal(err)
	}
	readExact(t, second, "still-live")
	c.Close()
	if requests.Load() != 2 || s.count.Load() != 1 {
		t.Fatal("replayed or replaced sibling")
	}
}

func TestGOAWAYKeepsAcceptedStreamAndReportsUnprocessed(t *testing.T) {
	var requests atomic.Int32
	s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		p := newPeer(t, conn, 65535)
		if p == nil {
			return
		}
		for {
			f, err := p.fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				requests.Add(1)
				if f.StreamID == 1 {
					p.success(1, values(f)["tiana-request-id"], false)
				} else {
					p.fr.WriteGoAway(1, http2.ErrCodeNo, []byte("CANARY_PRIVATE_DEBUG"))
				}
			case *http2.DataFrame:
				if f.StreamID == 1 {
					p.fr.WriteData(1, f.StreamEnded(), f.Data())
				}
			}
		}
	})
	c := clientFor(t, s, nil)
	first := connectFor(t, c, context.Background())
	_, err := c.Connect(context.Background(), HranaHTTP)
	var typed *Error
	if !errors.As(err, &typed) || typed.Committed || !typed.Unprocessed || typed.Retryable() || typed.RequestID == "" {
		t.Fatalf("GOAWAY metadata: %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "CANARY_PRIVATE_DEBUG") {
		t.Fatal("debug leaked")
	}
	if _, err := first.Write([]byte("accepted")); err != nil {
		t.Fatal(err)
	}
	readExact(t, first, "accepted")
	if err := first.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	c.Close()
	if requests.Load() != 2 || s.count.Load() != 1 {
		t.Fatal("automatic retry")
	}
}

func TestRetryableRequiresGatewayHint(t *testing.T) {
	if (&Error{Unprocessed: true}).Retryable() {
		t.Fatal("unprocessed alone is not the Gateway retry hint")
	}
	for _, e := range []*Error{{Status: 503, Code: "POLICY_UNAVAILABLE"}, {Status: 407, Code: "ACCESS_DENIED", RetryAfter: time.Second}, {Status: 503, Code: "POLICY_UNAVAILABLE", RetryAfter: 61 * time.Second}, {Status: 503, Code: "POLICY_UNAVAILABLE", RetryAfter: time.Second, Committed: true}} {
		if e.Retryable() {
			t.Fatalf("unexpected retryable: %v", e)
		}
	}
}

func TestDeadlinesAndClientCloseReleaseBlockedReaders(t *testing.T) {
	s := echoServer(t)
	c := clientFor(t, s, nil)
	stream := connectFor(t, c, context.Background())
	readExact(t, stream, "HELLO")
	stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	stream.SetDeadline(time.Time{})
	if _, err := stream.Write([]byte("after-deadline")); err != nil {
		t.Fatal(err)
	}
	readExact(t, stream, "after-deadline")
	done := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); done <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var typed *Error
		if !errors.As(err, &typed) || typed.Kind != Closed || !typed.Committed {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release Read")
	}
	if _, err := c.Connect(context.Background(), HranaHTTP); err == nil {
		t.Fatal("closed client connected")
	}
}

func TestLimitsAndSecretFormatting(t *testing.T) {
	s := echoServer(t)
	c := clientFor(t, s, func(cfg *Config) { cfg.MaxStreams = 1; cfg.Token = syntheticToken(t) })
	stream := connectFor(t, c, context.Background())
	_, err := c.Connect(context.Background(), HranaHTTP)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != Limit {
		t.Fatal(err)
	}
	token := syntheticToken(t)
	for _, v := range []any{token, Config{Token: token}, c, stream} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", v, v, v), token.value) {
			t.Fatal("secret formatting leak")
		}
	}
	stream.Close()
	next := connectFor(t, c, context.Background())
	next.Close()
}
