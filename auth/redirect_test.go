package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// These requests must never reach a redirect target: refresh credentials are
// in the body, so filtering Authorization alone cannot protect them.
func TestRefreshRejectsRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, destination := range []string{"same-origin", "cross-origin", "http-downgrade"} {
			for _, custom := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/custom=%t", status, destination, custom), func(t *testing.T) {
					var targetCalls atomic.Int32
					success := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						targetCalls.Add(1)
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprint(w, `{"access_token":"replacement","refresh_token":"replacement-refresh","expires_in":3600}`)
					})
					var target *httptest.Server
					if destination == "http-downgrade" {
						target = httptest.NewServer(success)
					} else {
						target = httptest.NewTLSServer(success)
					}
					defer target.Close()
					location := target.URL + "/target"
					if destination == "same-origin" {
						location = "/target"
					}
					origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/target" {
							success.ServeHTTP(w, r)
							return
						}
						http.Redirect(w, r, location, status)
					}))
					defer origin.Close()
					roots := x509.NewCertPool()
					roots.AddCert(origin.Certificate())
					if destination != "http-downgrade" {
						roots.AddCert(target.Certificate())
					}
					store := NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), origin.URL)
					before := Credential{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", ExpiresAt: time.Now().Add(time.Hour)}
					if err := store.Save(before); err != nil {
						t.Fatal(err)
					}
					config := Config{Origin: origin.URL, RootCAs: roots, Store: store}
					var policyCalls atomic.Int32
					caller := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
						policyCalls.Add(1)
						return nil
					}}
					if custom {
						config.HTTPClient = caller
					}
					client, err := NewWithConfig(config)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_, err = client.Refresh(ctx)
					var apiErr *APIError
					if !errors.As(err, &apiErr) || apiErr.Status != status {
						t.Errorf("expected original redirect status %d, got %v", status, err)
					}
					if targetCalls.Load() != 0 {
						t.Error("request reached redirect target")
					}
					after, loadErr := store.Load()
					if loadErr != nil || after.RefreshToken != before.RefreshToken || after.AccessToken != before.AccessToken {
						t.Error("redirect changed stored credentials")
					}
					if custom {
						if policyCalls.Load() != 0 {
							t.Error("SDK delegated redirect security to caller policy")
						}
						if caller.CheckRedirect(nil, nil) != nil || policyCalls.Load() == 0 {
							t.Error("SDK changed caller's redirect policy")
						}
					}
				})
			}
		}
	}
}
