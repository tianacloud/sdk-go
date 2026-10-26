package tiana

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/proxytest"
	"github.com/tianacloud/sdk-go/outbound"
	"golang.org/x/net/http2"
)

func TestGatewayThroughExplicitProxy(t *testing.T) {
	for _, kind := range []string{"http", "https", "socks5h"} {
		t.Run(kind, func(t *testing.T) {
			received := make(chan string, 1)
			server := listenTest(t, testTLS(t, "endpoint"), func(c *tls.Conn) {
				(&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != testEndpoint+testEndpointSuffix+":443" {
						t.Error("network port changed Gateway authority")
					}
					received <- r.Header.Get("Proxy-Authorization")
					echoHandler(w, r)
				})})
			})
			var peer *proxytest.Proxy
			if kind == "socks5h" {
				peer = proxytest.SOCKS(t, server.listener.Addr().String(), true)
			} else {
				peer = proxytest.HTTP(t, server.listener.Addr().String(), kind == "https")
				peer.RequireAuth = true
			}
			u, _ := url.Parse(peer.URL)
			u.User = url.UserPassword("user", "pass")
			policy, err := outbound.New(outbound.Config{AllProxy: u.String(), ProxyRootCAs: peer.Roots})
			if err != nil {
				t.Fatal(err)
			}
			token := syntheticToken(t)
			c, err := NewClient(Config{Endpoint: testEndpoint + testEndpointSuffix, Port: "9443", Network: policy, RootCAs: testRoots(t, "endpoint"), Token: token})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stream, err := c.Connect(ctx, HranaHTTP)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			readExact(t, stream, "HELLO")
			if _, err = stream.Write([]byte("opaque")); err != nil {
				t.Fatal(err)
			}
			readExact(t, stream, "opaque")
			if err = stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			readExact(t, stream, "EOF")
			if got := <-received; got != "Bearer "+token.value {
				t.Fatal("target credential changed")
			}
			r := peer.Requests()
			if len(r) != 1 || r[0].Address != testEndpoint+testEndpointSuffix+":9443" {
				t.Fatalf("proxy route: %+v", r)
			}
			if r[0].Authorization != "" && r[0].Authorization != "Basic dXNlcjpwYXNz" {
				t.Fatal("target bearer reached proxy")
			}
		})
	}
}

func TestOuterProxyRefusalIsNotGatewayStatus(t *testing.T) {
	peer := proxytest.HTTP(t, "127.0.0.1:1", false)
	peer.RequireAuth = true
	policy, err := outbound.New(outbound.Config{AllProxy: peer.URL})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(Config{Endpoint: testEndpoint + testEndpointSuffix, Network: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Connect(context.Background(), Git)
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != Proxy || failure.ProxyStatus != 407 || failure.Status != 0 || failure.Committed || failure.RequestID == "" {
		t.Fatalf("proxy identity/status: %v", err)
	}
	if len(peer.Requests()) != 1 {
		t.Fatal("refusal retried")
	}
}
