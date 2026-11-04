//go:build linux || darwin

package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAccountStoreSharedDirectory(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "current-owner"
		if foreign {
			name = "different-owner"
		}
		t.Run(name, func(t *testing.T) {
			if foreign && os.Geteuid() != 0 {
				t.Skip("chown fixture requires root")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "credentials.json")
			if err := os.Chmod(dir, 0777); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				path:           `{"credentials":{"https://mgr.example.test":{"access_token":"old","refresh_token":"old"}}}`,
				path + ".lock": "",
			} {
				if err := os.WriteFile(name, []byte(body), 0666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(name, 0666); err != nil {
					t.Fatal(err)
				}
				if foreign {
					if err := os.Chown(name, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			}
			if foreign {
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			store := NewFileStore(path, "https://mgr.example.test")
			if got, err := store.Load(); err != nil || got.AccessToken != "old" {
				t.Fatalf("load: %v", err)
			}
			if err := store.Save(Credential{AccessToken: "new", RefreshToken: "new"}); err != nil {
				t.Fatal(err)
			}
			if got, err := store.Load(); err != nil || got.AccessToken != "new" {
				t.Fatalf("reload: %v", err)
			}
			if err := store.Delete(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
