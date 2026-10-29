package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/proxytest"
)

func parsed(s string) *url.URL { u, _ := url.Parse(s); return u }

func TestRoutingAndCopies(t *testing.T) {
	cases := []struct {
		name         string
		config       Config
		target, want string
		fail         bool
	}{
		{"direct", Config{}, "https://target.example.test", "", false},
		{"no HTTP fallback", Config{HTTPProxy: "http://h.example.test"}, "https://target.example.test", "", false},
		{"all HTTPS", Config{AllProxy: "socks5h://a.example.test"}, "https://target.example.test", "socks5h://a.example.test:1080", false},
		{"all HTTP", Config{AllProxy: "socks5://a.example.test"}, "http://target.example.test", "socks5://a.example.test:1080", false},
		{"specific", Config{AllProxy: "http://a.example.test", HTTPSProxy: "https://s.example.test"}, "https://target.example.test", "https://s.example.test:443", false},
		{"suffix", Config{AllProxy: "http://a.example.test", NoProxy: "example.test"}, "https://target.example.test", "", false},
		{"subdomain only", Config{AllProxy: "http://a.example.test", NoProxy: ".example.test"}, "https://target.example.test", "", false},
		{"apex excluded", Config{AllProxy: "http://a.example.test", NoProxy: ".example.test"}, "https://example.test", "http://a.example.test:80", false},
		{"port", Config{AllProxy: "http://a.example.test", NoProxy: "target.example.test:9443"}, "https://target.example.test:9443", "", false},
		{"port miss", Config{AllProxy: "http://a.example.test", NoProxy: "target.example.test:9443"}, "https://target.example.test", "http://a.example.test:80", false},
		{"CIDR", Config{AllProxy: "http://a.example.test", NoProxy: "192.0.2.0/24"}, "https://192.0.2.1", "", false},
		{"IP", Config{AllProxy: "http://a.example.test", NoProxy: "192.0.2.1"}, "https://192.0.2.1", "", false},
		{"IPv6 CIDR", Config{AllProxy: "http://a.example.test", NoProxy: "2001:db8::/32"}, "https://[2001:db8::1]", "", false},
		{"localhost", Config{AllProxy: "http://a.example.test"}, "https://localhost", "", false},
		{"IPv4 loopback", Config{AllProxy: "http://a.example.test"}, "https://127.0.0.2", "", false},
		{"IPv6 loopback", Config{AllProxy: "http://a.example.test"}, "https://[::1]", "", false},
		{"wildcard", Config{AllProxy: "http://a.example.test", NoProxy: "*"}, "https://target.example.test", "", false},
		{"loopback CGI", Config{HTTPProxy: "http://a.example.test", CGI: true}, "http://[::1]", "", false},
		{"CGI explicit", Config{HTTPProxy: "http://a.example.test", AllProxy: "http://b.example.test", CGI: true}, "http://target.example.test", "", true},
		{"CGI bypass", Config{HTTPProxy: "http://a.example.test", NoProxy: "example.test", CGI: true}, "http://target.example.test", "", false},
		{"CGI all", Config{AllProxy: "http://a.example.test", CGI: true}, "http://target.example.test", "http://a.example.test:80", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			u, err := p.ProxyForURL(parsed(tc.target))
			if (err != nil) != tc.fail {
				t.Fatalf("error: %v", err)
			}
			got := ""
			if u != nil {
				got = u.String()
				u.Host = "changed.example.test"
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if u != nil {
				next, _ := p.ProxyForURL(parsed(tc.target))
				if next.Host == u.Host {
					t.Fatal("shared mutable proxy URL")
				}
			}
		})
	}
}

func TestSOCKSCredentialByteBounds(t *testing.T) {
	for _, size := range []int{0, 1, 255, 256} {
		for _, field := range []string{"username", "password"} {
			user, password := "user", "pass"
			if field == "username" {
				user = strings.Repeat("u", size)
			} else {
				password = strings.Repeat("p", size)
			}
			u := parsed("socks5h://proxy.example.test")
			u.User = url.UserPassword(user, password)
			_, err := New(Config{AllProxy: u.String()})
			if (err == nil) != (size >= 1 && size <= 255) {
				t.Fatalf("%s byte length %d accepted=%t", field, size, err == nil)
			}
		}
	}
}

func TestInvalidConfigurationRedaction(t *testing.T) {
	for _, raw := range []string{"bad://user:secret@proxy.example.test", "http://proxy.example.test:0", "http://proxy.example.test:01", "http://proxy.example.test/secret", "http://proxy.example.test?secret", "http://proxy.example.test#", "socks5://user@proxy.example.test", "socks5://user:@proxy.example.test", "socks5://" + strings.Repeat("u", 256) + ":secret@proxy.example.test", "http://user:%0asecret@proxy.example.test", strings.Repeat("x", MaxProxyBytes+1)} {
		_, err := New(Config{AllProxy: raw, HTTPSProxy: "http://good.example.test"})
		if err == nil || strings.Contains(fmt.Sprintf("%+v", err), "secret") {
			t.Fatal("invalid or secret configuration accepted/exposed")
		}
	}
	c := Config{AllProxy: "http://user:secret@proxy.example.test"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(verb, c), "secret") {
			t.Fatal("config formatting leak")
		}
	}
}

func echo(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func TestRealProxyHandshakeAndRemoteDNS(t *testing.T) {
	for _, kind := range []string{"http", "https", "socks5", "socks5h", "socks-auth"} {
		t.Run(kind, func(t *testing.T) {
			backend := echo(t)
			var peer *proxytest.Proxy
			if strings.HasPrefix(kind, "socks") {
				peer = proxytest.SOCKS(t, backend, kind == "socks-auth")
			} else {
				peer = proxytest.HTTP(t, backend, kind == "https")
			}
			u := parsed(peer.URL)
			if kind == "socks5" {
				u.Scheme = "socks5"
			}
			if kind == "socks-auth" || kind == "http" {
				u.User = url.UserPassword("user", "pass")
				peer.RequireAuth = true
			}
			p, err := New(Config{AllProxy: u.String(), ProxyRootCAs: peer.Roots})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := p.DialTunnel(ctx, Target{URL: parsed("https://unresolvable.example.test:9443")})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Write([]byte("opaque")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 6)
			if _, err = io.ReadFull(c, b); err != nil || string(b) != "opaque" {
				t.Fatalf("echo: %s %v", b, err)
			}
			r := peer.Requests()
			if len(r) != 1 || r[0].Address != "unresolvable.example.test:9443" {
				t.Fatalf("routes: %+v", r)
			}
		})
	}
}

func TestHTTPResponseBoundsAndPrefetchedBytes(t *testing.T) {
	for _, reply := range []string{"HTTP/1.1 200 OK\r\n\r\nopaque", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("x", 16<<10) + "\r\n\r\n", "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: x\r\n", 65) + "\r\n", "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n"} {
		r := bufio.NewReader(strings.NewReader(reply))
		_, err := responseHead(r)
		if strings.HasSuffix(reply, "opaque") {
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(r)
			if string(b) != "opaque" {
				t.Fatal("lost prefetch")
			}
		} else if err == nil {
			t.Fatal("unbounded/malformed head accepted")
		}
	}
}

func TestCancelHungProxyNoFallback(t *testing.T) {
	for _, scheme := range []string{"http", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.Accept()
				if e == nil {
					defer c.Close()
					_, _ = io.Copy(io.Discard, c)
				}
			}()
			p, err := New(Config{AllProxy: scheme + "://" + l.Addr().String()})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			_, err = p.DialTunnel(ctx, Target{URL: parsed("https://unresolvable.example.test")})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancel: %v", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("proxy socket leaked")
			}
		})
	}
}

func TestPhysicalOverrideAndSetupDeadlineHandoff(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			backend := echo(t)
			var peer *proxytest.Proxy
			if strings.HasPrefix(scheme, "socks") {
				peer = proxytest.SOCKS(t, backend, false)
			} else {
				peer = proxytest.HTTP(t, backend, scheme == "https")
			}
			u := parsed(peer.URL)
			u.Scheme = scheme
			// NO_PROXY matches logical targets, not the physical override.
			p, err := New(Config{AllProxy: u.String(), NoProxy: "192.0.2.10", ProxyRootCAs: peer.Roots})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			c, err := p.DialTunnel(ctx, Target{URL: parsed("https://identity.example.test:9443"), DialAddress: "192.0.2.10:10443"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			<-ctx.Done()
			// Neither setup cancellation nor its deadline may own the stream
			// after a successful handoff. A separate watchdog bounds this test.
			watchdog := time.AfterFunc(time.Second, func() { c.Close() })
			defer watchdog.Stop()
			if _, err := c.Write([]byte("after")); err != nil {
				t.Fatal("setup context closed a handed-off connection", err)
			}
			var reply [5]byte
			if _, err := io.ReadFull(c, reply[:]); err != nil || string(reply[:]) != "after" {
				t.Fatal("setup deadline survived handoff", err)
			}
			requests := peer.Requests()
			if len(requests) != 1 || requests[0].Address != "192.0.2.10:10443" {
				t.Fatal("physical override bypassed proxy or changed destination")
			}
			local, err := p.DialTunnel(context.Background(), Target{URL: parsed("https://identity.example.test"), DialAddress: backend})
			if err != nil {
				t.Fatal(err)
			}
			local.Close()
			if len(peer.Requests()) != 1 {
				t.Fatal("physical loopback override did not stay local")
			}
		})
	}
}

func TestSOCKSUsesLiteralIPWireTypes(t *testing.T) {
	for _, tc := range []struct {
		host     string
		wireType byte
	}{{"192.0.2.1", 1}, {"2001:db8::1", 4}} {
		peer := proxytest.SOCKS(t, echo(t), false)
		p, err := New(Config{AllProxy: peer.URL})
		if err != nil {
			t.Fatal(err)
		}
		address := net.JoinHostPort(tc.host, "9443")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := p.DialTunnel(ctx, Target{URL: parsed("https://" + address)})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		r := peer.Requests()
		if len(r) != 1 || r[0].Address != address || r[0].AddressType != tc.wireType {
			t.Fatalf("incorrect SOCKS IP request: %+v", r)
		}
	}
}
