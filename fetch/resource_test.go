package fetch

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNativeResourceHTTPOverConnectPreservesEncodedBodyAndHead(t *testing.T) {
	const endpoint = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{endpoint}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte{0x1f, 0x8b, 0x08, 0, 7, 8, 9}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Tiana-Database-Protocol") != "tiana-http" {
			t.Error("expected native CONNECT profile")
			return
		}
		w.Header()["Date"] = nil
		w.Header()["Content-Type"] = nil
		w.Header().Set("tiana-tunnel-version", "1")
		w.Header().Set("tiana-request-id", r.Header.Get("tiana-request-id"))
		w.Header().Set("tiana-auth-mode", "DISABLED")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		inner, err := http.ReadRequest(bufio.NewReader(r.Body))
		if err != nil {
			t.Error(err)
			return
		}
		if inner.URL.RequestURI() != "/asset?literal=1" || inner.Header.Get("Accept-Encoding") != "gzip" || inner.Header.Get("Authorization") != "" || inner.Header.Get("Proxy-Authorization") != "" {
			t.Error("native HTTP/header forwarding")
		}
		_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\nConnection: close\r\n\r\n")
		if inner.Method != "HEAD" {
			_, _ = w.Write(encoded)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done() // Keep the duplex CONNECT stream until the caller closes it.
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client, err := NewResourceClient(Config{Endpoint: endpoint, DialAddress: server.Listener.Addr().String(), RootCAs: roots, Token: "tia_1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, method := range []string{"GET", "HEAD"} {
		response, err := client.Do(context.Background(), Request{Method: method, PathQuery: "/asset?literal=1", Headers: []Header{{"accept-encoding", "gzip"}}})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.Status != 200 || response.Header.Get("Content-Encoding") != "gzip" || response.Header.Get("Content-Length") != "7" || method == "GET" && string(body) != string(encoded) || method == "HEAD" && len(body) != 0 {
			t.Fatalf("native %s representation mismatch: %v", method, err)
		}
	}
}
func TestNativeResourceRejectsMutationBeforeDialAndBoundsBody(t *testing.T) {
	client, err := NewResourceClient(Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test", DialAddress: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, request := range []Request{{Method: "PUT", PathQuery: "/publish"}, {Method: "GET", PathQuery: "//foreign"}, {Method: "GET", PathQuery: "/asset", Headers: []Header{{"host", "foreign"}}}} {
		if _, err := client.Do(context.Background(), request); !errors.Is(err, ErrProtocol) {
			t.Fatalf("expected local protocol rejection: %v", err)
		}
	}
	body := &resourceBody{body: io.NopCloser(strings.NewReader("abcd")), stream: io.NopCloser(strings.NewReader("")), cancel: func() {}, left: 3}
	if _, err := io.ReadAll(body); !errors.Is(err, ErrProtocol) {
		t.Fatal("unbounded native body")
	}
}
