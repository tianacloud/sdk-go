//go:build linux || darwin || windows

package auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/tianacloud/sdk-go/internal/localfile"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
