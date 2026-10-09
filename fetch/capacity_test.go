package fetch

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCapacityFailurePreservesCodeAndDoesNotReplay(t *testing.T) {
	for _, code := range []string{"ACTIVATION_RESOURCE_PRESSURE", "ACTIVATION_NO_IDLE_POD", "ACTIVATION_CAPACITY_UNAVAILABLE"} {
		t.Run(code, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"`+code+`","retryable":true}}`)
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client, err := NewClient(Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test", DialAddress: server.Listener.Addr().String(), RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.transport.TLSClientConfig.ServerName = "example.com"
			_, err = client.Do(t.Context(), Request{RequestID: "req-capacity", Method: "PUT", PathQuery: "/write", Body: strings.NewReader("one"), BodyLength: 3})
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != code || typed.Status != 503 || typed.RequestID != "req-capacity" || requests.Load() != 1 {
				t.Fatalf("error=%v requests=%d", err, requests.Load())
			}
		})
	}
}
