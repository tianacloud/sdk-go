package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each accepted socket is owned and joined by the fixture, including failure
// paths. Counting accepts detects retries without relying on error text.
func scriptedProxy(t *testing.T, run func(net.Conn)) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var mu sync.Mutex
	var sockets []net.Conn
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			mu.Lock()
			sockets = append(sockets, c)
			mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); run(c) }()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		// Join the accept loop before taking the final snapshot of sockets.
		<-acceptDone
		mu.Lock()
		for _, c := range sockets {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().String(), &calls
}

func readGreeting(c net.Conn) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return false
	}
	_, err := io.CopyN(io.Discard, c, int64(h[1]))
	return err == nil
}

func readAuthentication(c net.Conn) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 {
		return false
	}
	if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return false
	}
	_, err := io.CopyN(io.Discard, c, int64(h[0]))
	return err == nil
}

func readDomainConnect(c net.Conn) bool {
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] != 1 || h[3] != 3 {
		return false
	}
	_, err := io.CopyN(io.Discard, c, int64(h[4])+2)
	return err == nil
}

func TestEveryProxyHandshakeStageCancelsAndCloses(t *testing.T) {
	for _, stage := range []string{"https-tls", "http-header", "socks-method", "socks-auth", "socks-connect"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%t", stage, deadline), func(t *testing.T) {
				ready, closed := make(chan struct{}), make(chan struct{})
				address, calls := scriptedProxy(t, func(c net.Conn) {
					defer close(closed)
					if stage == "https-tls" {
						var first [1]byte
						if _, err := io.ReadFull(c, first[:]); err != nil {
							return
						}
					} else if stage == "http-header" {
						if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
							return
						}
						_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Slow: ")
					} else {
						if !readGreeting(c) {
							return
						}
						if stage != "socks-method" {
							_, _ = c.Write([]byte{5, 2})
							if !readAuthentication(c) {
								return
							}
							if stage == "socks-connect" {
								_, _ = c.Write([]byte{1, 0})
								if !readDomainConnect(c) {
									return
								}
							}
						}
					}
					close(ready)
					_, _ = io.Copy(io.Discard, c)
				})
				scheme := "socks5h://user:proxy-canary@"
				if stage == "https-tls" {
					scheme = "https://"
				} else if stage == "http-header" {
					scheme = "http://"
				}
				p, err := New(Config{AllProxy: scheme + address})
				if err != nil {
					t.Fatal(err)
				}
				var ctx context.Context
				var cancel context.CancelFunc
				if deadline {
					ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					c, err := p.DialTunnel(ctx, Target{URL: parsed("https://target.example.test")})
					if c != nil {
						c.Close()
					}
					done <- err
				}()
				select {
				case <-ready:
				case <-time.After(2 * time.Second):
					t.Fatal("proxy never reached the intended handshake stage")
				}
				want := context.DeadlineExceeded
				if !deadline {
					cancel()
					want = context.Canceled
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) || calls.Load() != 1 {
						t.Fatalf("cancellation or retry: %v, accepts=%d", err, calls.Load())
					}
				case <-time.After(2 * time.Second):
					t.Fatal("proxy dial did not cancel")
				}
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("proxy socket survived failed establishment")
				}
			})
		}
	}
}

func TestMalformedSOCKSRepliesDoNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name, stage string
		reply       []byte
	}{
		{"method-version", "method", []byte{4, 0}},
		{"no-method", "method", []byte{5, 255}},
		{"unsupported-method", "method", []byte{5, 3}},
		{"auth-version", "auth", []byte{2, 0}},
		{"auth-rejected", "auth", []byte{1, 1}},
		{"connect-version", "connect", []byte{4, 0, 0, 1}},
		{"connect-rejected", "connect", []byte{5, 5, 0, 1}},
		{"connect-reserved", "connect", []byte{5, 0, 1, 1}},
		{"connect-address-type", "connect", []byte{5, 0, 0, 9}},
		{"connect-eof", "connect", []byte{5, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, calls := scriptedProxy(t, func(c net.Conn) {
				if !readGreeting(c) {
					return
				}
				if tc.stage != "method" {
					_, _ = c.Write([]byte{5, 2})
					if !readAuthentication(c) {
						return
					}
					if tc.stage == "connect" {
						_, _ = c.Write([]byte{1, 0})
						if !readDomainConnect(c) {
							return
						}
					}
				}
				_, _ = c.Write(tc.reply)
			})
			p, err := New(Config{AllProxy: "socks5h://user:proxy-canary@" + address})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := p.DialTunnel(ctx, Target{URL: parsed("https://target.example.test")})
			if c != nil {
				c.Close()
				t.Fatal("malformed SOCKS proxy was accepted")
			}
			var failure *Error
			if !errors.As(err, &failure) || failure.Kind != Connect || calls.Load() != 1 {
				t.Fatalf("malformed SOCKS reply: %v, accepts=%d", err, calls.Load())
			}
		})
	}
}
