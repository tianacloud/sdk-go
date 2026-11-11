package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tianacloud/sdk-go/internal/proxytest"
	"github.com/tianacloud/sdk-go/outbound"
)

func TestFetchPublicationAndStatusThroughProxy(t *testing.T) {
	const endpoint = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test"
	for _, kind := range []string{"http", "https", "socks5h"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.TLS.ServerName != endpoint || r.Header.Get("Authorization") != "Bearer opaque-tenant-credential" || r.Header.Get("Proxy-Authorization") != "" {
					t.Error("target identity/credential isolation")
				}
				var frame [10]byte
				_, _ = io.ReadFull(r.Body, frame[:])
				raw := make([]byte, binary.BigEndian.Uint32(frame[6:]))
				_, _ = io.ReadFull(r.Body, raw)
				var m metadata
				if json.Unmarshal(raw, &m) != nil {
					t.Error("metadata")
				}
				body, _ := io.ReadAll(r.Body)
				if m.Method == "PUT" && string(body) != "archive" {
					t.Error("publication body")
				}
				response, _ := canonicalJSON(struct {
					Version int      `json:"metadata_version"`
					ID      string   `json:"request_id"`
					Status  int      `json:"status"`
					Text    string   `json:"status_text"`
					Headers []Header `json:"headers"`
					Length  int      `json:"body_length"`
				}{1, m.RequestID, 200, "OK", []Header{}, 2})
				copy(frame[:4], "TFS1")
				binary.BigEndian.PutUint32(frame[6:], uint32(len(response)))
				w.Header().Set("Content-Type", mediaType)
				w.Header().Set("Cache-Control", "no-store")
				w.Write(frame[:])
				w.Write(response)
				w.Write([]byte("{}"))
			}))
			cert, err := tls.LoadX509KeyPair("../testdata/tls/endpoint_certificate.pem", "../testdata/tls/endpoint_key.pem")
			if err != nil {
				t.Fatal(err)
			}
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			var peer *proxytest.Proxy
			if kind == "socks5h" {
				peer = proxytest.SOCKS(t, server.Listener.Addr().String(), false)
			} else {
				peer = proxytest.HTTP(t, server.Listener.Addr().String(), kind == "https")
			}
			policy, err := outbound.New(outbound.Config{AllProxy: peer.URL, ProxyRootCAs: peer.Roots})
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(Config{Endpoint: endpoint, RootCAs: roots, Network: policy, Token: "opaque-tenant-credential"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, request := range []Request{{Method: "PUT", PathQuery: "/_tiana/web/publish", Body: strings.NewReader("archive"), BodyLength: 7}, {Method: "GET", PathQuery: "/_tiana/web/current"}, {Method: "GET", PathQuery: "/_tiana/web/publish/receipt"}} {
				response, err := client.Do(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = io.ReadAll(response.Body); err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
			}
			if calls != 3 || len(peer.Requests()) != 1 || peer.Requests()[0].Address != endpoint+":443" {
				t.Fatalf("fetch did not reuse the proxied connection: calls=%d dials=%d", calls, len(peer.Requests()))
			}
		})
	}
}
