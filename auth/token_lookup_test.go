package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLookupTokenIdentityExpiryAndOrdering(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "tokens.json")
	s := NewFileInstanceTokenStore(path, "https://mgr.example")
	base := InstanceTokenCredential{TenantID: "tenant", InstanceID: "instance", EndpointID: "ep-one", TokenID: "one", Token: "secret-one", ExpiresAt: InstanceTokenNoExpiry, SavedAt: now}
	for _, tc := range []struct {
		name   string
		change func(*InstanceTokenCredential)
		found  bool
	}{
		{"match", func(c *InstanceTokenCredential) {}, true},
		{"origin", func(c *InstanceTokenCredential) { c.Origin = "https://other.example" }, false},
		{"instance", func(c *InstanceTokenCredential) { c.InstanceID = "other" }, false},
		{"endpoint", func(c *InstanceTokenCredential) { c.EndpointID = "other" }, false},
		{"missing-endpoint", func(c *InstanceTokenCredential) { c.EndpointID = "" }, false},
		{"expired", func(c *InstanceTokenCredential) { c.ExpiresAt = now.Add(-time.Second).Unix() }, false},
		{"near-expiry", func(c *InstanceTokenCredential) { c.ExpiresAt = now.Add(time.Second).Unix() }, false},
		{"expiry-cutoff", func(c *InstanceTokenCredential) { c.ExpiresAt = now.Add(30 * time.Second).Unix() }, false},
		{"finite-usable", func(c *InstanceTokenCredential) { c.ExpiresAt = now.Add(31 * time.Second).Unix() }, true},
		{"long-lived", func(c *InstanceTokenCredential) { c.ExpiresAt = 1<<63 - 1 }, true},
		{"missing-expiry", func(c *InstanceTokenCredential) { c.ExpiresAt = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewFileInstanceTokenStore(filepath.Join(t.TempDir(), "tokens.json"), "https://mgr.example")
			c := base
			tc.change(&c)
			if _, err := s.Save(c); err != nil {
				t.Fatal(err)
			}
			got, err := s.Lookup("instance", "ep-one", now)
			if tc.found {
				if err != nil || got.Token != base.Token {
					t.Fatalf("matching token unavailable: %v", err)
				}
			} else if !errors.Is(err, ErrInstanceTokenNotFound) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	if _, err := s.Save(base); err != nil {
		t.Fatal(err)
	}
	newer := base
	newer.TokenID = "two"
	newer.Token = "secret-two"
	newer.SavedAt = now.Add(time.Second)
	if _, err := s.Save(newer); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup("instance", "ep-one", now)
	if err != nil || got.TokenID != "two" {
		t.Fatal("newest usable token not selected", err)
	}
	newer.TenantID = "other-tenant"
	newer.TokenID = "three"
	if _, err := s.Save(newer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("instance", "ep-one", now); err == nil {
		t.Fatal("accepted ambiguous tenant")
	}
}

func TestLookupTokenPrivateFileAndNoMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	s := NewFileInstanceTokenStore(path, "https://mgr.example")
	if _, err := s.Lookup("instance", "endpoint", time.Now()); !errors.Is(err, ErrInstanceTokenNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Save(InstanceTokenCredential{TenantID: "tenant", InstanceID: "instance", EndpointID: "endpoint", TokenID: "one", Token: "secret", ExpiresAt: InstanceTokenNoExpiry}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := s.Lookup("instance", "endpoint", time.Now()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("lookup rewrote store")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("instance", "endpoint", time.Now()); err == nil {
		t.Fatal("accepted public credential file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileInstanceTokenStore(link, s.Origin).Lookup("instance", "endpoint", time.Now()); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.WriteFile(path, []byte("not json SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("instance", "endpoint", time.Now()); err == nil || err.Error() != "invalid local InstanceToken store" {
		t.Fatal("unsafe corrupt-file error", err)
	}
}
