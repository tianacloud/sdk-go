//go:build windows

package localfile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateFilesAndLimits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "中文 directory")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	f, err := CreateTemp(dir, "credential-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if _, err := f.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := Read(path, 6, true); err != nil || string(data) != "secret" {
		t.Fatalf("private read: %q %v", data, err)
	}
	if _, err := Read(path, 5, true); err == nil {
		t.Fatal("accepted oversized file")
	}
	if _, err := Read(dir, 64, false); err == nil {
		t.Fatal("accepted directory")
	}
	if _, err := Read("NUL", 64, false); err == nil {
		t.Fatal("accepted device")
	}
	if _, err := Read(filepath.Join(dir, "missing"), 64, true); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, true); err == nil {
		t.Fatal("accepted public ACL")
	}
	if data, err := Read(path, 64, false); err != nil || string(data) != "secret" {
		t.Fatalf("ordinary file: %q %v", data, err)
	}
}

func TestWindowsLockCancellationAndPersistentIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "store.lock")
	unlock, err := Lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if release, err := Lock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("contended lock: %v", err)
	}
	unlock()
	release, err := Lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	release()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("lock identity changed: %v", err)
	}
	link := filepath.Join(dir, "alias.lock")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if release, err := Lock(context.Background(), path); err == nil {
		release()
		t.Fatal("accepted multiply linked lock")
	}
}

func TestWindowsLockProcessExit(t *testing.T) {
	if path := os.Getenv("TIANA_TEST_LOCK_PATH"); path != "" {
		release, err := Lock(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if err := os.WriteFile(path+".ready", []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour)
	}
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "process.lock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsLockProcessExit$")
	cmd.Env = append(os.Environ(), "TIANA_TEST_LOCK_PATH="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not acquire lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if release, err := Lock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("cross-process exclusion: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	release, err := Lock(ctx2, path)
	if err != nil {
		t.Fatalf("crash did not release lock: %v", err)
	}
	release()
}

func TestWindowsPrivateReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	f, err := CreateTemp(dir, "target-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(f.Name(), link); err != nil {
		t.Skipf("symlink creation needs developer mode or privilege: %v", err)
	}
	if _, err := Read(link, 64, true); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestWindowsLockRejectsPublicACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.lock")
	release, err := Lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	release()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if release, err := Lock(context.Background(), path); err == nil {
		release()
		t.Fatal("accepted public lock ACL")
	}
}

func TestWindowsPrivateDirectoryRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := PrivateDir(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks need developer mode or privilege: %v", err)
	}
	if err := PrivateDir(link); err == nil {
		t.Fatal("accepted directory symlink")
	}
}

func TestWindowsPrivateDirectoryACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := PrivateDir(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(user.User.Sid) {
		t.Fatalf("directory owner: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		t.Fatalf("directory must have one owner grant: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != 0x001f01ff || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		t.Fatal("directory grants access outside current user")
	}
}
