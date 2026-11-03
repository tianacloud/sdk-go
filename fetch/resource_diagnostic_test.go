package fetch

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResourceHTTPFailureRetainsStreamIdentity(t *testing.T) {
	for _, bodyFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[bodyFailure], func(t *testing.T) {
			ids := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := r.Header.Get("tiana-request-id")
				ids <- id
				w.Header()["Date"] = nil
				w.Header()["Content-Type"] = nil
				w.Header().Set("tiana-tunnel-version", "1")
				w.Header().Set("tiana-request-id", id)
				w.Header().Set("tiana-auth-mode", "DISABLED")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if _, err := http.ReadRequest(bufio.NewReader(r.Body)); err != nil {
					t.Error(err)
					return
				}
				if bodyFailure {
					io.WriteString(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\ninvalid-size\r\n")
				} else {
					io.WriteString(w, "bad response\r\n\r\n")
				}
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			certificate, err := tls.LoadX509KeyPair("../testdata/tls/endpoint_certificate.pem", "../testdata/tls/endpoint_key.pem")
			if err != nil {
				t.Fatal(err)
			}
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client, err := NewResourceClient(Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test", DialAddress: server.Listener.Addr().String(), RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(t.Context(), Request{Method: "GET", PathQuery: "/"})
			if bodyFailure && response == nil {
				t.Fatalf("expected body phase: %v", err)
			}
			if response != nil {
				defer response.Body.Close()
				_, err = io.ReadAll(response.Body)
			}
			if len(ids) == 0 {
				t.Fatalf("request did not reach peer: %v", err)
			}
			id := <-ids
			var requestErr *Error
			if !errors.As(err, &requestErr) || requestErr.RequestID != id || id == "" {
				t.Fatalf("resource failure identity: %#v", err)
			}
		})
	}
}
