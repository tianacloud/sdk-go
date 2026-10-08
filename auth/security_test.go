//go:build linux || darwin

package auth

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthRejectsRemotePlaintext(t *testing.T) {
	for _, origin := range []string{"http://mgr.example.test", "http://localhost.example.test", "http://192.0.2.1", "http://0.0.0.0", "http://[::]"} {
		if _, err := NewWithConfig(Config{Origin: origin}); err == nil {
			t.Errorf("accepted remote plaintext origin %s", origin)
		}
	}
	for _, origin := range []string{"https://mgr.example.test", "http://127.0.0.1:1234", "http://[::1]:1234", "http://localhost:1234"} {
		if _, err := NewWithConfig(Config{Origin: origin}); err != nil {
			t.Errorf("rejected supported origin: %v", err)
		}
	}
}
func TestPeerErrorDiagnosticsNeverReflectSecrets(t *testing.T) {
	const canary = "SYNTHETIC_SECRET"
	response := &http.Response{StatusCode: 409, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"COMMIT_STATUS_UNKNOWN","message":"SYNTHETIC_SECRET\u001b[31m","operation_id":"op-123","command_not_after":"2026-01-01T00:00:00Z","secret_recoverable":true}}`))}
	err := parseAPIError(response).(*APIError)
	if err.OperationID != "op-123" || !err.SecretRecoverable || err.CommandNotAfter == "" {
		t.Fatal("recovery metadata lost")
	}
	for _, value := range []any{err, *err, &APIError{Code: canary, Message: canary, OperationID: canary}} {
		if text := fmt.Sprintf("%v %+v %#v", value, value, value); strings.Contains(text, canary) || strings.Contains(text, "\x1b") {
			t.Fatal("peer data leaked in diagnostic")
		}
	}
	if strings.Contains(err.Message, canary) {
		t.Fatal("Message retains unsafe peer text")
	}
}
func TestAccountStoreRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "fifo", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "credentials.json")
			body := []byte(`{"credentials":{"https://mgr.example.test":{"access_token":"access","refresh_token":"refresh"}}}`)
			switch kind {
			case "symlink":
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, body, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, body, 0644); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, make([]byte, 8*1024*1024+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			store := NewFileStore(path, "https://mgr.example.test")
			if _, err := store.Load(); err == nil {
				t.Error("unsafe Load accepted")
			}
			if err := store.Save(Credential{AccessToken: "new", RefreshToken: "new"}); err == nil {
				t.Error("unsafe Save accepted")
			}
			if err := store.Delete(); err == nil {
				t.Error("unsafe Delete accepted")
			}
		})
	}
}
func TestUnsafeLockFilesFailBeforeNetwork(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "public", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "credentials.json")
			store := NewFileStore(path, server.URL)
			previous := Credential{AccessToken: "old", RefreshToken: "old"}
			if err := store.Save(previous); err != nil {
				t.Fatal(err)
			}
			lockPath := path + ".lock"
			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			} // No holder exists in this synthetic fixture.
			switch kind {
			case "symlink":
				if err := os.Symlink(path, lockPath); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(lockPath, 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(lockPath, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, lockPath); err != nil {
					t.Fatal(err)
				}
			}
			client, _ := NewWithConfig(Config{Origin: server.URL, Store: store})
			if _, err := client.Refresh(context.Background()); err == nil {
				t.Fatal("unsafe lock accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("network sent before acquiring safe lock")
			}
			if got, err := store.Load(); err != nil || got.RefreshToken != previous.RefreshToken {
				t.Fatal("credential changed after lock failure")
			}
		})
	}
}

func TestAuthOutputBoundaries(t *testing.T) {
	for _, value := range []string{"http://remote.example.test/auth", "javascript:alert(1)", "https://user:secret@example.test/auth", "https://example.test/auth\x1b[31m", strings.Repeat("a", 4097)} {
		if safeBrowserURL(value) {
			t.Fatal("unsafe browser URL accepted")
		}
	}
	label := safeUserLabel("name\x1b[31m\n\u202e" + strings.Repeat("x", 1000))
	if len(label) > 260 || strings.ContainsAny(label, "\x1b\n\u202e") {
		t.Fatal("unsafe login label")
	}
}

type securityMemoryStore struct {
	mu         sync.Mutex
	credential Credential
	deletes    int
}

func (s *securityMemoryStore) Load() (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credential, nil
}
func (s *securityMemoryStore) Save(c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credential = c
	return nil
}
func (s *securityMemoryStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	s.credential = Credential{}
	return nil
}

func TestInvalidGrantNeverDeletesChangedCustomStore(t *testing.T) {
	previous := Credential{AccessToken: "old", RefreshToken: "old"}
	next := Credential{AccessToken: "next", RefreshToken: "next", ExpiresAt: time.Now().Add(time.Hour)}
	store := &securityMemoryStore{credential: previous}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = store.Save(next)
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()
	client, err := NewWithConfig(Config{Origin: server.URL, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Refresh(context.Background())
	if err != nil || got.RefreshToken != next.RefreshToken || store.deletes != 0 {
		t.Fatalf("replacement deleted: %v", err)
	}
}

func TestInstanceTokenSaveRejectsUnsafeExistingStore(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tokens.json")
			switch kind {
			case "public":
				if err := os.WriteFile(path, []byte(`{"tokens":{}}`), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".target"
				if err := os.WriteFile(target, []byte(`{"tokens":{}}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			store := NewFileInstanceTokenStore(path, "https://mgr.example.test")
			if _, err := store.Save(InstanceTokenCredential{TenantID: "t", InstanceID: "i", TokenID: "id", Token: "synthetic"}); err == nil {
				t.Fatal("unsafe token store overwritten")
			}
		})
	}
}

func TestMalformedHTTPDiagnosticsNeverReflectSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "SYNTHETIC_SECRET\r\n\r\n")
	}))
	defer server.Close()
	client, err := NewWithConfig(Config{Origin: server.URL, Store: &securityMemoryStore{credential: Credential{AccessToken: "synthetic", RefreshToken: "synthetic"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(context.Background())
	if err == nil {
		t.Fatal("malformed HTTP accepted")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "SYNTHETIC_SECRET") {
		t.Fatal("transport diagnostic echoed peer bytes")
	}
}
