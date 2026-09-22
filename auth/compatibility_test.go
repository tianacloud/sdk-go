package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/auth"
)

func TestCurrentCLICredentialFiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	dir := filepath.Join(root, "tiana")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Literal current on-disk shapes; tokens below are synthetic test inputs.
	account := `{"credentials":{"https://mgr.example.test":{"access_token":"old-access","refresh_token":"old-refresh","token_type":"Bearer","expires_at":"2099-01-01T00:00:00Z","user":{"user_id":"user-one"}}}}`
	tokens := `{"tokens":{"https://mgr.example.test|tenant-one|token-one":{"origin":"https://mgr.example.test","tenant_id":"tenant-one","instance_id":"instance-one","endpoint_id":"endpoint-one","token_id":"token-one","token":"synthetic-instance-token","expires_at":-1,"saved_at":"2026-01-01T00:00:00Z"}}}`
	for name, body := range map[string]string{"credentials.json": account, "instance-tokens.json": tokens} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := auth.New("https://mgr.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := client.EnsureCredential(context.Background())
	if err != nil || credential.AccessToken != "old-access" {
		t.Fatalf("legacy account load: %v", err)
	}
	store, err := auth.NewInstanceTokenStore("https://mgr.example.test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.LookupCandidates("tenant-one", []string{"token-one"}, time.Now())
	if err != nil || token.Token != "synthetic-instance-token" {
		t.Fatalf("legacy token load: %v", err)
	}
	accountStore, err := auth.NewCredentialStore("https://mgr.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := accountStore.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := accountStore.Load(); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("account deletion: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "instance-tokens.json"))
	if err != nil || string(after) != tokens {
		t.Fatal("account logout changed instance credentials")
	}
}

func TestAuthorizedRequestRefreshAndNoServerErrorReplay(t *testing.T) {
	var calls, refreshes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/auth/refresh" {
			refreshes++
			json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600})
			return
		}
		calls++
		if r.Header.Get("Idempotency-Key") != "stable-key" {
			t.Error("idempotency changed")
		}
		if r.Header.Get("Authorization") == "Bearer old-access" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}
		w.WriteHeader(503)
		w.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer server.Close()
	store := auth.NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL)
	if err := store.Save(auth.Credential{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewWithConfig(auth.Config{Origin: server.URL, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.DoJSON(context.Background(), http.MethodPost, "/operation", map[string]string{"value": "same"}, map[string]string{"Idempotency-Key": "stable-key"}, nil)
	if status != 503 || err == nil || calls != 2 || refreshes != 1 {
		t.Fatalf("status=%d calls=%d refreshes=%d err=%v", status, calls, refreshes, err)
	}
}

func TestOriginEnvironmentHasNoCompiledFallback(t *testing.T) {
	t.Setenv("TIANA_MGR_ORIGIN", "")
	t.Setenv("TIANA_AUTH_ORIGIN", "")
	if auth.DefaultOrigin() != "" {
		t.Fatal("unexpected deployment fallback")
	}
	if _, err := auth.New(""); err == nil {
		t.Fatal("missing origin accepted")
	}
	t.Setenv("TIANA_AUTH_ORIGIN", "https://auth.example.test")
	if auth.DefaultOrigin() != "https://auth.example.test" {
		t.Fatal("auth origin ignored")
	}
	t.Setenv("TIANA_MGR_ORIGIN", "https://mgr.example.test")
	if auth.DefaultOrigin() != "https://mgr.example.test" {
		t.Fatal("MGR priority changed")
	}
}

func TestFormattingDoesNotRevealCredentials(t *testing.T) {
	const canary = "synthetic-private-canary"
	for _, value := range []any{auth.Credential{AccessToken: canary, RefreshToken: canary}, auth.InstanceTokenCredential{Token: canary}, auth.AuthTransaction{ClientSecret: canary}, auth.PollResult{AuthorizationCode: canary}, auth.Config{Origin: canary}, &auth.Credential{AccessToken: canary}, &auth.InstanceTokenCredential{Token: canary}, &auth.AuthTransaction{ClientSecret: canary}, &auth.PollResult{AuthorizationCode: canary}, &auth.Config{Origin: canary}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), canary) {
				t.Fatal("credential disclosed by formatting")
			}
		}
	}
}

func TestConstructorsDoNotAccessCredentialFiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	if _, err := auth.New("https://mgr.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewInstanceTokenStore("https://mgr.example.test"); err != nil {
		t.Fatal(err)
	}
	path, err := auth.DefaultCredentialPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("constructor created directory")
	}
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("intentionally invalid credential file")
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.New("https://mgr.example.test"); err != nil {
		t.Fatal("constructor read file", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(corrupt) {
		t.Fatal("constructor rewrote file")
	}
}
