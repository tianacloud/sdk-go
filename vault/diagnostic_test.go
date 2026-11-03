package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tianacloud/sdk-go/fetch"
)

func TestVaultErrorsKeepRequestIDAndBusinessMeaning(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{403, `{"error":{"code":"INVALID_SIGNATURE"}}`, nil},
		{404, `{"error":{"code":"NOT_FOUND"}}`, ErrNotExist},
		{504, `{"error":{"code":"RESULT_UNKNOWN"}}`, ErrResultUnknown},
		{503, `{"error":{"code":"BUSY"}}`, nil},
		{200, `{`, ErrResultUnknown},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			ids := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var head [10]byte
				if _, err := io.ReadFull(r.Body, head[:]); err != nil {
					t.Error(err)
					return
				}
				raw := make([]byte, binary.BigEndian.Uint32(head[6:]))
				if _, err := io.ReadFull(r.Body, raw); err != nil {
					t.Error(err)
					return
				}
				var request struct {
					RequestID string `json:"request_id"`
				}
				if err := json.Unmarshal(raw, &request); err != nil {
					t.Error(err)
					return
				}
				ids <- request.RequestID
				raw = []byte(fmt.Sprintf(`{"metadata_version":1,"request_id":%q,"status":%d,"status_text":"Result","headers":[],"body_length":%d}`, request.RequestID, tc.status, len(tc.body)))
				copy(head[:4], "TFS1")
				binary.BigEndian.PutUint32(head[6:], uint32(len(raw)))
				w.Header().Set("Content-Type", "application/vnd.tiana.fetch.v1")
				w.Header().Set("Cache-Control", "no-store")
				w.Write(head[:])
				w.Write(raw)
				io.WriteString(w, tc.body)
			}))
			certificate, err := tls.LoadX509KeyPair("../testdata/tls/endpoint_certificate.pem", "../testdata/tls/endpoint_key.pem")
			if err != nil {
				t.Fatal(err)
			}
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			transport, err := fetch.NewClient(fetch.Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test", DialAddress: server.Listener.Addr().String(), RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			client, err := NewClient(transport, "vault-fixture", "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.List(t.Context(), "", "", 1)
			if len(ids) == 0 {
				t.Fatalf("request did not reach test server: %v", err)
			}
			id := <-ids
			var requestErr *Error
			if !errors.As(err, &requestErr) || requestErr.RequestID != id || id == "" || requestErr.Status != tc.status {
				t.Fatalf("Vault error identity: %#v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("business meaning: %v", err)
			}
			var output bytes.Buffer
			log.New(&output, "", 0).Print(err)
			if !strings.Contains(output.String(), "request_id="+id) {
				t.Errorf("Vault diagnostic log: %q", output.String())
			}
			if tc.status == 403 && requestErr.Code != "INVALID_SIGNATURE" {
				t.Fatalf("error code: %#v", requestErr)
			}
			if tc.status == 503 && requestErr.Code != "BUSY" {
				t.Fatalf("error code: %#v", requestErr)
			}
		})
	}
}
