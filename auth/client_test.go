package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testClient(t *testing.T, server *httptest.Server, store CredentialStore, output *bytes.Buffer) *Client {
	t.Helper()
	client, err := NewWithConfig(Config{
		Origin: server.URL, HTTPClient: server.Client(), Store: store, Output: output,
		PollInterval: time.Millisecond, Hostname: "headless-test", Platform: "linux",
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCurrentSessionReadsTenantIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/transactions/whoami" || r.Header.Get("Authorization") != "Bearer access" {
			t.Fatalf("request %s", r.URL.Path)
		}
		io.WriteString(w, `{"user":{"user_id":"principal","tenant_id":"tenant","email":"user@example.test"}}`)
	}))
	defer server.Close()
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL)
	if err := store.Save(Credential{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := testClient(t, server, store, new(bytes.Buffer)).CurrentSession(context.Background())
	if err != nil || got.ID != "principal" || got.TenantID != "tenant" {
		t.Fatalf("session=%+v err=%v", got, err)
	}
}

func TestLoginHTTPFlowStoresCredentialAndKeepsSecretsOutOfOutput(t *testing.T) {
	const clientSecret = "ats_client_secret_should_not_be_printed"
	const authorizationCode = "ac_authorization_code_should_not_be_printed"
	const accessToken = "access_token_should_not_be_printed"
	const refreshToken = "refresh_token_should_not_be_printed"
	var mu sync.Mutex
	pollCalls := 0
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(body))
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/auth/transactions":
			if r.Method != http.MethodPost {
				t.Errorf("transaction method=%s", r.Method)
			}
			var request struct {
				Purpose string         `json:"purpose"`
				Client  clientMetadata `json:"client"`
			}
			if err := json.Unmarshal(body, &request); err != nil || request.Purpose != "cli_login" || request.Client.Type != "cli" || request.Client.Hostname != "headless-test" {
				t.Errorf("transaction request=%s", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"transaction_id":"at_test","client_secret":"`+clientSecret+`","user_code":"H7K9-M2PX","verification_uri":"https://auth.example/api/v1/device","verification_uri_complete":"https://auth.example/api/v1/a/H7K9-M2PX","expires_in":600,"poll_interval":0}`)
		case "/api/v1/auth/transactions/at_test/poll":
			pollCalls++
			if pollCalls == 1 {
				_, _ = io.WriteString(w, `{"status":"pending","retry_after":0}`)
			} else {
				_, _ = io.WriteString(w, `{"status":"approved","authorization_code":"`+authorizationCode+`","expires_in":30}`)
			}
		case "/api/v1/auth/token":
			var request map[string]string
			if err := json.Unmarshal(body, &request); err != nil || request["client_secret"] != clientSecret || request["authorization_code"] != authorizationCode || request["grant_type"] != "auth_transaction" {
				t.Errorf("token request=%s", body)
			}
			_, _ = io.WriteString(w, `{"access_token":"`+accessToken+`","refresh_token":"`+refreshToken+`","token_type":"Bearer","expires_in":3600,"account_created":true,"user":{"user_id":"usr_test","email":"xin@example.com","display_name":"Xin"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	store := NewFileStore(filepath.Join(t.TempDir(), "nested", "credentials.json"), server.URL)
	var output bytes.Buffer
	client := testClient(t, server, store, &output)
	credential, err := client.Login(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credential.AccessToken != accessToken || credential.RefreshToken != refreshToken || credential.User.Email != "xin@example.com" {
		t.Fatalf("credential=%+v", credential)
	}
	if !strings.Contains(output.String(), "Open:\nhttps://auth.example/api/v1/a/H7K9-M2PX") || !strings.Contains(output.String(), "✓ Account created") || !strings.Contains(output.String(), "✓ Signed in as xin@example.com") {
		t.Fatalf("output=%q", output.String())
	}
	for _, secret := range []string{clientSecret, authorizationCode, accessToken, refreshToken} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("output leaked %q: %q", secret, output.String())
		}
	}
	saved, err := store.Load()
	if err != nil || saved.AccessToken != accessToken || saved.RefreshToken != refreshToken {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
	if pollCalls != 2 {
		t.Fatalf("poll calls=%d, want 2", pollCalls)
	}
	for _, body := range received {
		if strings.Contains(body, accessToken) || strings.Contains(body, refreshToken) {
			t.Fatalf("request leaked issued token: %s", body)
		}
	}
}

func TestRunAuthenticatedLogsInBeforeOperationWithoutRetryingIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/transactions":
			_, _ = io.WriteString(w, `{"transaction_id":"at_middleware","client_secret":"secret","user_code":"H7K9-M2PX","verification_uri_complete":"https://auth.example/api/v1/a/H7K9-M2PX","expires_in":600,"poll_interval":0}`)
		case "/api/v1/auth/transactions/at_middleware/poll":
			_, _ = io.WriteString(w, `{"status":"approved","authorization_code":"code","expires_in":30}`)
		case "/api/v1/auth/token":
			_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"user":{"user_id":"usr_middleware","email":"middleware@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	client := testClient(t, server, NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL), &output)
	var calls int
	err := client.RunAuthenticated(context.Background(), func(_ context.Context, credential Credential) error {
		calls++
		if credential.User.ID != "usr_middleware" || credential.AccessToken != "access" {
			t.Fatalf("credential=%+v", credential)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("operation calls=%d", calls)
	}
	if !strings.Contains(output.String(), "You need to authenticate.") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestRefreshRotatesCredentialAndLogoutDeletesLocalCredential(t *testing.T) {
	var refreshCalls, logoutCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/refresh":
			refreshCalls++
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "old-refresh") {
				t.Errorf("refresh body=%s", body)
			}
			_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`)
		case "/api/v1/auth/transactions/logout":
			logoutCalls++
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "new-refresh") {
				t.Errorf("logout body=%s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL)
	if err := store.Save(Credential{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Minute), User: User{Email: "old@example.com"}}); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, server, store, new(bytes.Buffer))
	credential, err := client.EnsureCredential(context.Background())
	if err != nil || credential.AccessToken != "new-access" || credential.RefreshToken != "new-refresh" {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls=%d", refreshCalls)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout calls=%d", logoutCalls)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("credential after logout err=%v", err)
	}
}

func TestAPIErrorDoesNotExposeResponseBody(t *testing.T) {
	const secret = "response-body-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate_limited","retry_after":2,"secret":"`+secret+`"}`)
	}))
	defer server.Close()
	client := testClient(t, server, NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL), new(bytes.Buffer))
	_, err := client.CreateAuthTransaction(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error=%v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "rate_limited" || apiErr.RetryAfter != 2*time.Second {
		t.Fatalf("api error=%+v", err)
	}
}

func TestFileStorePermissionsAndOriginIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "tiana", "credentials.json")
	first := NewFileStore(path, "https://one.example/")
	second := NewFileStore(path, "https://two.example")
	credential := Credential{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}
	if err := first.Save(credential); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("cross-origin load err=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%o", info.Mode().Perm())
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%o", directoryInfo.Mode().Perm())
	}
	if err := first.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("deleted credential err=%v", err)
	}
}

func TestBrowserAuthActionDoesNotContainClientSecret(t *testing.T) {
	transaction := AuthTransaction{ID: "at_test", ClientSecret: "secret", VerificationURIComplete: "https://auth.example/api/v1/a/H7K9-M2PX", ExpiresIn: 600}
	encoded, err := json.Marshal(transaction.BrowserAction())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || !strings.Contains(string(encoded), `"error":"user_action_required"`) || !strings.Contains(string(encoded), `"type":"browser_auth"`) {
		t.Fatalf("action=%s", encoded)
	}
}

func TestInvalidRefreshRemovesLocalCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","refresh_token":"must-not-escape"}`)
	}))
	defer server.Close()
	store := NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL)
	if err := store.Save(Credential{AccessToken: "expired", RefreshToken: "revoked", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, server, store, new(bytes.Buffer))
	if _, err := client.EnsureCredential(context.Background()); !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("EnsureCredential err=%v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("credential after invalid refresh err=%v", err)
	}
}

func TestLoginHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/transactions":
			_, _ = io.WriteString(w, `{"transaction_id":"at_cancel","client_secret":"secret","user_code":"H7K9-M2PX","verification_uri_complete":"https://auth.example/api/v1/a/H7K9-M2PX","expires_in":600,"poll_interval":1}`)
		case "/api/v1/auth/transactions/at_cancel/poll":
			_, _ = io.WriteString(w, `{"status":"pending","retry_after":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := testClient(t, server, NewFileStore(filepath.Join(t.TempDir(), "credentials.json"), server.URL), new(bytes.Buffer))
	if _, err := client.Login(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Login err=%v", err)
	}
}
