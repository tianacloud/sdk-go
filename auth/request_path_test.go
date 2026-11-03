package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestManagementPathPreservesEncodedSecretKey(t *testing.T) {
	for _, key := range []string{"production/db", "literal%2Fkey", "含 空格/符号?#"} {
		t.Run(key, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expected := "/api/v1/secrets-store/secrets/" + key
				if r.URL.Path != expected || r.URL.Query().Get("keyword") != "a/b" {
					t.Errorf("path %q query %q", r.URL.Path, r.URL.RawQuery)
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			origin, _ := url.Parse(server.URL)
			c := &Client{origin: origin, http: server.Client()}
			_, err := c.doJSONWithHeadersStatus(context.Background(), "PUT", "/api/v1/secrets-store/secrets/"+url.PathEscape(key)+"?keyword=a%2Fb", nil, "synthetic", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
