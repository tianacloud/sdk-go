package tiana

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const testEndpointSuffix = ".db.example.test"

const testEndpoint = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz"

func testRoots(t *testing.T, name string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile("testdata/tls/" + name + "_certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("invalid fixture")
	}
	return roots
}

func testTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("testdata/tls/"+name+"_certificate.pem", "testdata/tls/"+name+"_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
}

func syntheticToken(t *testing.T) *Token {
	t.Helper()
	token, err := NewToken("tia_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type testListener struct {
	listener net.Listener
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
	count    atomic.Int32
}

func listenTest(t *testing.T, config *tls.Config, handle func(*tls.Conn)) *testListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testListener{listener: listener}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.count.Add(1)
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				tlsConn := tls.Server(conn, config)
				if tlsConn.Handshake() == nil {
					handle(tlsConn)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		s.mu.Lock()
		for _, conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func clientFor(t *testing.T, server *testListener, change func(*Config)) *Client {
	t.Helper()
	cfg := Config{Endpoint: testEndpoint + testEndpointSuffix, DialAddress: server.listener.Addr().String(), RootCAs: testRoots(t, "endpoint"), ConnectTimeout: 2 * time.Second, ResponseTimeout: 2 * time.Second}
	if change != nil {
		change(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func connectFor(t *testing.T, c *Client, ctx context.Context) *Tunnel {
	t.Helper()
	stream, err := c.Connect(ctx, HranaHTTP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header()["Date"] = nil
	w.Header()["Content-Type"] = nil
	w.Header().Set("tiana-tunnel-version", "1")
	w.Header().Set("tiana-request-id", r.Header.Get("tiana-request-id"))
	w.Header().Set("tiana-auth-mode", "DISABLED")
	w.WriteHeader(200)
	w.(http.Flusher).Flush()
	w.Write([]byte("HELLO"))
	w.(http.Flusher).Flush()
	buf := make([]byte, 8192)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		if err != nil {
			break
		}
	}
	w.Write([]byte("EOF"))
	w.(http.Flusher).Flush()
}

func echoServer(t *testing.T) *testListener {
	return listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(echoHandler)})
	})
}

func TestOpaqueTokenReachesGatewayUnchanged(t *testing.T) {
	const secret = "opaque-group-secret-with-arbitrary-prefix-and-length"
	received := make(chan string, 1)
	server := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r.Header.Get("Proxy-Authorization")
			echoHandler(w, r)
		})})
	})
	token, err := NewToken(secret)
	if err != nil {
		t.Fatal(err)
	}
	client := clientFor(t, server, func(config *Config) { config.Token = token })
	tunnel := connectFor(t, client, context.Background())
	defer tunnel.Close()
	select {
	case got := <-received:
		if got != "Bearer "+secret {
			t.Fatalf("credential changed: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway did not receive credential")
	}
}

func readExact(t *testing.T, r io.Reader, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Fatalf("unexpected bytes, got %d", len(buf))
	}
}

func TestDuplexFlowControlHalfCloseAndSharedSession(t *testing.T) {
	s := echoServer(t)
	c := clientFor(t, s, nil)
	first := connectFor(t, c, context.Background())
	second := connectFor(t, c, context.Background())
	if s.count.Load() != 1 {
		t.Fatal("expected shared physical connection")
	}
	readExact(t, first, "HELLO")
	readExact(t, second, "HELLO")
	payload := bytes.Repeat([]byte("\x00test\xff"), 350000)
	writeDone := make(chan error, 1)
	go func() {
		_, err := first.Write(payload)
		if err == nil {
			err = first.CloseWrite()
		}
		writeDone <- err
	}()
	got, err := io.ReadAll(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(payload, []byte("EOF")...)) {
		t.Fatalf("byte mismatch: %d", len(got))
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("sibling")); err != nil {
		t.Fatal(err)
	}
	readExact(t, second, "sibling")
	if err := second.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readExact(t, second, "EOF")
	if _, err := second.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF: %v", err)
	}
	if err := second.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

type wirePeer struct {
	conn net.Conn
	fr   *http2.Framer
	mu   sync.Mutex
}

func newPeer(t *testing.T, conn net.Conn, initialWindow uint32) *wirePeer {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil
	}
	if string(preface) != http2.ClientPreface {
		t.Error("invalid preface")
		return nil
	}
	p := &wirePeer{conn: conn, fr: http2.NewFramer(conn, conn)}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(0, nil)
	p.fr.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: initialWindow})
	return p
}

func (p *wirePeer) success(id uint32, requestID string, end bool, extra ...hpack.HeaderField) {
	fields := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "tiana-tunnel-version", Value: "1"}, {Name: "tiana-request-id", Value: requestID}, {Name: "tiana-auth-mode", Value: "DISABLED"}}
	p.headers(id, end, append(fields, extra...)...)
}

func (p *wirePeer) headers(id uint32, end bool, fields ...hpack.HeaderField) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(0)
	enc.SetMaxDynamicTableSize(0)
	for _, field := range fields {
		enc.WriteField(field)
	}
	p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: end, BlockFragment: buf.Bytes()})
}

func values(frame *http2.MetaHeadersFrame) map[string]string {
	m := map[string]string{}
	for _, field := range frame.Fields {
		m[field.Name] = field.Value
	}
	return m
}

func TestWireTLSHeadersSensitiveAndBarrier(t *testing.T) {
	seen := make(chan bool, 1)
	s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		state := conn.ConnectionState()
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || state.ServerName != testEndpoint+testEndpointSuffix {
			t.Error("TLS identity mismatch")
		}
		p := newPeer(t, conn, 65535)
		if p == nil {
			return
		}
		var request *http2.MetaHeadersFrame
		for request == nil {
			frame, err := p.fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					if v, ok := f.Value(http2.SettingHeaderTableSize); !ok || v != 0 {
						t.Error("table size not zero")
					}
					if v, ok := f.Value(http2.SettingInitialWindowSize); !ok || v != 65535 {
						t.Error("window mismatch")
					}
					p.fr.WriteSettingsAck()
				}
			case *http2.MetaHeadersFrame:
				request = f
			case *http2.DataFrame:
				t.Error("pre-200 DATA")
			}
		}
		v := values(request)
		if len(v) != 7 || v[":method"] != "CONNECT" || v[":authority"] != testEndpoint+testEndpointSuffix+":443" || v["tiana-tunnel-version"] != "1" || v["tiana-database-protocol"] != "hrana-http" {
			t.Error("request header mismatch")
		}
		for _, field := range request.Fields {
			if field.Name == "proxy-authorization" && !field.Sensitive {
				t.Error("credential not never-indexed")
			}
		}
		conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		for {
			frame, err := p.fr.ReadFrame()
			if err != nil {
				break
			}
			if _, ok := frame.(*http2.DataFrame); ok {
				t.Error("pre-200 DATA")
			}
		}
		conn.SetReadDeadline(time.Time{})
		p.success(request.StreamID, v["tiana-request-id"], false)
		p.fr.WriteData(request.StreamID, false, []byte("first"))
		seen <- true
		for {
			if _, err := p.fr.ReadFrame(); err != nil {
				return
			}
		}
	})
	c := clientFor(t, s, func(cfg *Config) { cfg.Token = syntheticToken(t) })
	stream := connectFor(t, c, context.Background())
	readExact(t, stream, "first")
	<-seen
}

func TestRemoteHalfClosePreservesWrite(t *testing.T) {
	got := make(chan string, 1)
	s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		p := newPeer(t, conn, 65535)
		if p == nil {
			return
		}
		var body bytes.Buffer
		for {
			f, err := p.fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				p.success(f.StreamID, values(f)["tiana-request-id"], false)
				p.fr.WriteData(f.StreamID, true, []byte("remote-eof"))
			case *http2.DataFrame:
				body.Write(f.Data())
				if f.StreamEnded() {
					got <- body.String()
					return
				}
			}
		}
	})
	stream := connectFor(t, clientFor(t, s, nil), context.Background())
	result, err := io.ReadAll(stream)
	if err != nil || string(result) != "remote-eof" {
		t.Fatal("remote EOF failed", err)
	}
	if _, err := stream.Write([]byte("after-read-eof")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if <-got != "after-read-eof" {
		t.Fatal("lost write")
	}
}

func TestCancellationUnblocksReadAndPreservesSibling(t *testing.T) {
	s := echoServer(t)
	c := clientFor(t, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	stream := connectFor(t, c, ctx)
	sibling := connectFor(t, c, context.Background())
	readExact(t, stream, "HELLO")
	readExact(t, sibling, "HELLO")
	done := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); done <- err }()
	cancel()
	select {
	case err := <-done:
		var typed *Error
		if !errors.Is(err, context.Canceled) || !errors.As(err, &typed) || !typed.Committed || typed.Retryable() {
			t.Fatalf("wrong cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read not canceled")
	}
	if _, err := sibling.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	readExact(t, sibling, "alive")
}

func TestCancellationUnblocksFlowControlledWrite(t *testing.T) {
	reset := make(chan struct{}, 1)
	s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		p := newPeer(t, conn, 0)
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
				p.success(f.StreamID, values(f)["tiana-request-id"], false)
			case *http2.DataFrame:
				t.Error("DATA without credit")
			case *http2.RSTStreamFrame:
				reset <- struct{}{}
				return
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	stream := connectFor(t, clientFor(t, s, nil), ctx)
	done := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("blocked")); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write not canceled")
	}
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("missing RST")
	}
}

func TestErrorMappingAndNoReplay(t *testing.T) {
	cases := []struct {
		status int
		code   string
		retry  bool
	}{{403, "QUOTA_EXCEEDED", false}, {400, "MALFORMED_CONNECT", false}, {400, "EARLY_TUNNEL_DATA", false}, {407, "AUTH_REQUIRED", false}, {407, "ACCESS_DENIED", false}, {407, "AUTHORIZATION_EXPIRED", false}, {504, "CALLER_DEADLINE", false}, {421, "ENDPOINT_MISMATCH", false}, {429, "CONNECTION_LIMIT", true}, {503, "POLICY_UNAVAILABLE", true}, {503, "INSTANCE_UNAVAILABLE", true}, {504, "ACTIVATION_TIMEOUT", true}}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
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
					if f, ok := f.(*http2.MetaHeadersFrame); ok {
						requests.Add(1)
						p.headers(f.StreamID, true, hpack.HeaderField{Name: ":status", Value: fmt.Sprint(tc.status)}, hpack.HeaderField{Name: "tiana-error-code", Value: tc.code}, hpack.HeaderField{Name: "tiana-retry-after-ms", Value: "25"})
					}
				}
			})
			c := clientFor(t, s, nil)
			_, err := c.Connect(context.Background(), HranaHTTP)
			var typed *Error
			if !errors.As(err, &typed) || typed.Status != tc.status || typed.Code != tc.code || typed.Retryable() != tc.retry || typed.Committed {
				t.Fatalf("error mapping: %v", err)
			}
			c.Close()
			if requests.Load() != 1 {
				t.Fatal("request replayed")
			}
		})
	}
}

func TestSuccessHeadersClosedAndRedacted(t *testing.T) {
	secret := "CANARY_PEER_SECRET"
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
			if f, ok := f.(*http2.MetaHeadersFrame); ok {
				p.success(f.StreamID, values(f)["tiana-request-id"], false, hpack.HeaderField{Name: "x-extra", Value: secret})
			}
		}
	})
	_, err := clientFor(t, s, nil).Connect(context.Background(), HranaHTTP)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != Response || !typed.Committed {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", err, err), secret) {
		t.Fatal("peer bytes leaked")
	}
}

// Every profile must reach the Gateway verbatim, including server-first and
// half-close behavior: the SDK does not interpret the inner protocol.
func TestGatewayProfiles(t *testing.T) {
	for _, profile := range []Profile{HranaHTTP, HranaWebSocket, MySQL, PostgreSQL, Git} {
		t.Run(string(profile), func(t *testing.T) {
			observed := make(chan string, 1)
			s := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
				(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					observed <- r.Header.Get("tiana-database-protocol")
					echoHandler(w, r)
				})})
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := clientFor(t, s, nil).Connect(ctx, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if got := <-observed; got != string(profile) || stream.Metadata().Profile != profile {
				t.Fatalf("profile mismatch: %q", got)
			}
			if _, err := stream.Write([]byte("profile-bytes")); err != nil {
				t.Fatal(err)
			}
			if err := stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(stream)
			if err != nil || string(got) != "HELLOprofile-bytesEOF" {
				t.Fatalf("echo: %q, %v", got, err)
			}
		})
	}
}

func TestUnknownProfilesRejectedBeforeDial(t *testing.T) {
	server := echoServer(t)
	client := clientFor(t, server, nil)
	for _, profile := range []Profile{"", "MYSQL", "postgres", "fetch", "mysql\n"} {
		_, err := client.Connect(context.Background(), profile)
		var typed *Error
		if !errors.As(err, &typed) || typed.Kind != Configuration {
			t.Fatalf("profile %q: %v", profile, err)
		}
	}
	if server.count.Load() != 0 {
		t.Fatal("unsupported profile dialed a server")
	}
}
