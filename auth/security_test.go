//go:build linux || darwin

package auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/tianacloud/sdk-go/internal/localfile"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
func TestRefreshIndependentClientsReuseRotatedCredential(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credentials.json")
	previous := Credential{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Hour)}
	if err := NewFileStore(path, server.URL).Save(previous); err != nil {
		t.Fatal(err)
	}
	first, _ := NewWithConfig(Config{Origin: server.URL, Store: NewFileStore(path, server.URL)})
	second, _ := NewWithConfig(Config{Origin: server.URL, Store: NewFileStore(path, server.URL)})
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, client := range []*Client{first, second} {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			<-start
			got, err := c.refresh(context.Background(), previous)
			if err != nil || got.RefreshToken != "new-refresh" {
				t.Errorf("refresh result: %v", err)
			}
		}(client)
	}
	close(start)
	wg.Wait()
	if requests.Load() != 1 {
		t.Errorf("old refresh replayed %d times", requests.Load())
	}
	if got, err := first.LoadCredential(); err != nil || got.RefreshToken != "new-refresh" {
		t.Errorf("rotation destroyed: %v", err)
	}
}
func TestSecuritySubprocess(t *testing.T) {
	mode := os.Getenv("TIANA_SECURITY_TEST_HELPER")
	if mode == "" {
		return
	}
	path, origin := os.Getenv("TIANA_SECURITY_TEST_PATH"), os.Getenv("TIANA_SECURITY_TEST_ORIGIN")
	switch mode {
	case "hold":
		unlock, err := localfile.Lock(context.Background(), path+".lock")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Println("LOCKED")
		time.Sleep(time.Minute)

	case "refresh":
		client, err := NewWithConfig(Config{Origin: origin, Store: NewFileStore(path, origin)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.refresh(context.Background(), Credential{AccessToken: "old-access", RefreshToken: "old-refresh"})
		if err != nil {
			t.Fatal(err)
		}
	case "save":
		if err := NewFileStore(path, origin).Save(Credential{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh"}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRefreshAcrossProcesses(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := NewFileStore(path, server.URL).Save(Credential{AccessToken: "old-access", RefreshToken: "old-refresh"}); err != nil {
		t.Fatal(err)
	}
	runSecurityProcesses(t, "refresh", path, []string{server.URL, server.URL})
	if requests.Load() != 1 {
		t.Fatalf("refresh replayed across processes: %d", requests.Load())
	}
}
func TestStoreConcurrentProcessesPreserveOrigins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	origins := make([]string, 16)
	for i := range origins {
		origins[i] = fmt.Sprintf("https://mgr-%d.example.test", i)
	}
	runSecurityProcesses(t, "save", path, origins)
	for _, origin := range origins {
		if _, err := NewFileStore(path, origin).Load(); err != nil {
			t.Errorf("lost origin: %v", err)
		}
	}
}
func runSecurityProcesses(t *testing.T, mode, path string, origins []string) {
	t.Helper()
	var wg sync.WaitGroup
	for _, origin := range origins {
		wg.Add(1)
		go func(origin string) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestSecuritySubprocess$")
			cmd.Env = append(os.Environ(), "TIANA_SECURITY_TEST_HELPER="+mode, "TIANA_SECURITY_TEST_PATH="+path, "TIANA_SECURITY_TEST_ORIGIN="+origin)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("helper failed: %v: %s", err, output)
			}
		}(origin)
	}
	wg.Wait()
}
func TestRefreshLockCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credentials.json")
	previous := Credential{AccessToken: "old-access", RefreshToken: "old-refresh"}
	if err := NewFileStore(path, server.URL).Save(previous); err != nil {
		t.Fatal(err)
	}
	first, _ := NewWithConfig(Config{Origin: server.URL, Store: NewFileStore(path, server.URL)})
	second, _ := NewWithConfig(Config{Origin: server.URL, Store: NewFileStore(path, server.URL)})
	done := make(chan error, 1)
	go func() { _, err := first.refresh(context.Background(), previous); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := second.refresh(ctx, previous)
	close(release)
	<-done
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait ignored context: %v", err)
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

func TestLockReleasedOnProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecuritySubprocess$")
	cmd.Env = append(os.Environ(), "TIANA_SECURITY_TEST_HELPER=hold", "TIANA_SECURITY_TEST_PATH="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "LOCKED\n" {
		t.Fatalf("helper not ready: %v", err)
	}
	before, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if unlock, err := localfile.Lock(ctx, path+".lock"); err == nil {
		unlock()
		t.Error("cross-process lock was not exclusive")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Error(err)
	}
	cancel()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := localfile.Lock(ctx, path+".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	after, err := os.Stat(path + ".lock")
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("persistent lock inode was replaced")
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
