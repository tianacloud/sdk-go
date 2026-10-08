package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileInstanceTokenStoreKeysByOriginTenantInstanceAndToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "tiana", "instance-tokens.json")
	first := NewFileInstanceTokenStore(path, "https://one.example/")
	second := NewFileInstanceTokenStore(path, "https://two.example")
	credential := InstanceTokenCredential{
		TenantID: "ten_one", InstanceID: "inst_one", TokenID: "tok_one", Name: "default",
		Token: "tia_first", ExpiresAt: InstanceTokenNoExpiry, SavedAt: time.Now().UTC(),
	}
	if _, err := first.Save(credential); err != nil {
		t.Fatal(err)
	}
	credential.TokenID = "tok_two"
	credential.Token = "tia_second"
	if _, err := first.Save(credential); err != nil {
		t.Fatal(err)
	}
	credential.TokenID = "tok_three"
	credential.Token = "tia_third"
	if _, err := second.Save(credential); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file instanceTokenFile
	if err := json.Unmarshal(contents, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Tokens) != 3 {
		t.Fatalf("stored tokens=%d, want 3: %s", len(file.Tokens), contents)
	}
	for _, want := range []string{"tia_first", "tia_second", "tia_third"} {
		found := false
		for _, saved := range file.Tokens {
			found = found || saved.Token == want
		}
		if !found {
			t.Fatalf("token %q not stored: %s", want, contents)
		}
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
}

func TestFileInstanceTokenStoreRejectsIncompleteCredential(t *testing.T) {
	store := NewFileInstanceTokenStore(filepath.Join(t.TempDir(), "instance-tokens.json"), "https://one.example")
	if _, err := store.Save(InstanceTokenCredential{TenantID: "ten", InstanceID: "inst", TokenID: "tok"}); err == nil {
		t.Fatal("expected a missing secret to be rejected")
	}
}

func TestFileInstanceTokenStoreStoresOneSecretAcrossResourceMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance-tokens.json")
	store := NewFileInstanceTokenStore(path, "https://one.example")
	credential := InstanceTokenCredential{TenantID: "tenant", TokenID: "token", Token: "opaque", InstanceID: "first", ExpiresAt: InstanceTokenNoExpiry}
	if _, err := store.Save(credential); err != nil {
		t.Fatal(err)
	}
	credential.InstanceID = "second"
	if _, err := store.Save(credential); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file instanceTokenFile
	if err := json.Unmarshal(contents, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Tokens) != 1 {
		t.Fatalf("stored %d copies of one secret", len(file.Tokens))
	}
}
