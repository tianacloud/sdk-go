package tiana

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/gatewaydial"
	"github.com/tianacloud/sdk-go/internal/compattest"
	"github.com/tianacloud/sdk-go/outbound"
	"golang.org/x/net/http2"
)

func TestCompatPreservesTLSCredentialsProfilesAndSessionReuse(t *testing.T) {
	t.Run("override", func(t *testing.T) { checkCompatProfiles(t, false) })
	t.Run("default-address", func(t *testing.T) { checkCompatProfiles(t, true) })
}
func checkCompatProfiles(t *testing.T, defaultAddress bool) {
	endpoint := testEndpoint + testEndpointSuffix
	token := syntheticToken(t)
	var calls atomic.Int32
	server := listenTest(t, testTLS(t, "endpoint"), func(c *tls.Conn) {
		state := c.ConnectionState()
		if state.ServerName != endpoint || state.NegotiatedProtocol != "h2" || state.Version != tls.VersionTLS13 {
			t.Error("target TLS changed")
		}
		(&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.Host != endpoint+":443" || r.Header.Get("Proxy-Authorization") != "Bearer "+token.value {
				t.Error("original CONNECT identity or credential changed")
			}
			echoHandler(w, r)
		})})
	}, func(c net.Conn) error { return compattest.Accept(c, endpoint) })
	policy, err := outbound.New(outbound.Config{AllProxy: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if defaultAddress {
		compattest.ResolveLoopback(t, endpoint)
	}
	client := clientFor(t, server, func(c *Config) {
		c.Endpoint = endpoint
		c.Transport = gatewaydial.Compat
		c.Network = policy
		c.Token = token
		c.Port = "9443"
		if defaultAddress {
			_, c.Port, _ = net.SplitHostPort(c.DialAddress)
			c.DialAddress = ""
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, protocol := range []Profile{HranaHTTP, HranaWebSocket, MySQL, PostgreSQL, Git} {
		stream, err := client.Connect(ctx, protocol)
		if err != nil {
			t.Fatal(err)
		}
		readExact(t, stream, "HELLO")
		if _, err := stream.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
		readExact(t, stream, "data")
		if err := stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readExact(t, stream, "EOF")
		stream.Close()
	}
	if calls.Load() != 5 || server.count.Load() != 1 {
		t.Fatal("compat did not retain session reuse")
	}
}

func TestInvalidTransportFailsAtConstruction(t *testing.T) {
	_, err := NewClient(Config{Endpoint: testEndpoint + testEndpointSuffix, Transport: gatewaydial.Mode(255)})
	if err == nil {
		t.Fatal("invalid transport accepted")
	}
}

func TestCompatRetainsCertificateVerification(t *testing.T) {
	for _, certificate := range []string{"wrong", "unrelated"} {
		t.Run(certificate, func(t *testing.T) {
			endpoint := testEndpoint + testEndpointSuffix
			// The unrelated certificate fixture is a root, without a server key;
			// use the real endpoint cert with unrelated trust for that case.
			serverCert := certificate
			if certificate == "unrelated" {
				serverCert = "endpoint"
			}
			server := listenTest(t, testTLS(t, serverCert), func(*tls.Conn) {
				t.Error("application connection after invalid TLS")
			}, func(c net.Conn) error { return compattest.Accept(c, endpoint) })
			client := clientFor(t, server, func(c *Config) {
				c.Transport = gatewaydial.Compat
				c.RootCAs = testRoots(t, certificate)
			})
			_, err := client.Connect(context.Background(), Git)
			var failure *Error
			if !errors.As(err, &failure) || failure.Kind != TLS {
				t.Fatalf("certificate error: %v", err)
			}
		})
	}
}
