package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStoresPersistLocally(t *testing.T) {
	for _, useXDG := range []bool{false, true} {
		name := "home"
		if useXDG {
			name = "xdg"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", "")
			directory := filepath.Join(home, ".config", "tiana")
			if useXDG {
				config := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", config)
				directory = filepath.Join(config, "tiana")
			}
			const origin = "https://mgr.example"
			store, err := NewCredentialStore(origin + "/")
			if err != nil {
				t.Fatal(err)
			}
			credential := Credential{AccessToken: "access", RefreshToken: "refresh"}
			if err := store.Save(credential); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(filepath.Join(directory, "credentials.json"))
			if err != nil {
				t.Fatal(err)
			}
			var accounts credentialFile
			if err := json.Unmarshal(contents, &accounts); err != nil {
				t.Fatal(err)
			}
			if accounts.Credentials[origin].RefreshToken != credential.RefreshToken {
				t.Fatal("account credential was not saved locally")
			}
			reopened, err := NewCredentialStore(origin)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := reopened.Load(); err != nil || got.AccessToken != credential.AccessToken {
				t.Fatalf("reload credential: %v", err)
			}
			tokens, err := NewInstanceTokenStore(origin)
			if err != nil {
				t.Fatal(err)
			}
			location, err := tokens.Save(InstanceTokenCredential{TenantID: "tenant", InstanceID: "instance", TokenID: "token", Token: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			if location != filepath.Join(directory, "instance-tokens.json") {
				t.Fatalf("token location = %q", location)
			}
			contents, err = os.ReadFile(location)
			if err != nil {
				t.Fatal(err)
			}
			var savedTokens instanceTokenFile
			if err := json.Unmarshal(contents, &savedTokens); err != nil {
				t.Fatal(err)
			}
			if savedTokens.Tokens[origin+"|tenant|instance|token"].Token != "secret" {
				t.Fatal("instance token was not saved locally")
			}
			if err := reopened.Delete(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
				t.Fatalf("credential remains after logout: %v", err)
			}
			if _, err := os.Stat(location); err != nil {
				t.Fatalf("logout removed instance tokens: %v", err)
			}
		})
	}
}
