package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
			got, err := s.LookupCandidates(c.TenantID, []string{c.TokenID}, now)
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
	got, err := s.LookupCandidates("tenant", []string{"one", "two"}, now)
	if err != nil || got.TokenID != "two" {
		t.Fatal("newest usable token not selected", err)
	}
	newer.TenantID = "other-tenant"
	newer.TokenID = "three"
	if _, err := s.Save(newer); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LookupCandidates("tenant", []string{"one", "two", "three"}, now); err != nil || got.TenantID != "tenant" {
		t.Fatal("tenant isolation failed", err)
	}
}

func TestLookupTokenPrivateFileAndNoMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	s := NewFileInstanceTokenStore(path, "https://mgr.example")
	if _, err := s.LookupCandidates("tenant", []string{"one"}, time.Now()); !errors.Is(err, ErrInstanceTokenNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Save(InstanceTokenCredential{TenantID: "tenant", InstanceID: "instance", EndpointID: "endpoint", TokenID: "one", Token: "secret", ExpiresAt: InstanceTokenNoExpiry}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := s.LookupCandidates("tenant", []string{"one"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("lookup rewrote store")
	}
	if err := chmodFixtureFile(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupCandidates("tenant", []string{"one"}, time.Now()); err == nil {
		t.Fatal("accepted public credential file")
	}
	if err := chmodFixtureFile(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks need developer mode or privilege: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := NewFileInstanceTokenStore(link, s.Origin).LookupCandidates("tenant", []string{"one"}, time.Now()); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := writeFixtureFile(path, []byte("not json SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupCandidates("tenant", []string{"one"}, time.Now()); err == nil || err.Error() != "invalid local InstanceToken store" {
		t.Fatal("unsafe corrupt-file error", err)
	}
}

func TestCandidateSelectionUsesOnlyReturnedIDsAndStableOrdering(t *testing.T) {
	now := time.Now().UTC()
	store := NewFileInstanceTokenStore(filepath.Join(t.TempDir(), "tokens.json"), "https://mgr.example")
	for _, credential := range []InstanceTokenCredential{
		{TenantID: "tenant", TokenID: "old", Token: "old-secret", ExpiresAt: InstanceTokenNoExpiry, SavedAt: now},
		{TenantID: "tenant", TokenID: "new", Token: "new-secret", ExpiresAt: InstanceTokenNoExpiry, SavedAt: now.Add(time.Second)},
		{TenantID: "tenant", TokenID: "near", Token: "near-secret", ExpiresAt: now.Add(30 * time.Second).Unix(), SavedAt: now.Add(2 * time.Second)},
		{TenantID: "other", TokenID: "foreign", Token: "foreign-secret", ExpiresAt: InstanceTokenNoExpiry, SavedAt: now.Add(3 * time.Second)},
	} {
		if _, err := store.Save(credential); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := store.CandidateIDs("tenant", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("candidate IDs=%v", ids)
	}
	got, err := store.LookupCandidates("tenant", []string{"old", "foreign"}, now)
	if err != nil || got.TokenID != "old" {
		t.Fatalf("selection escaped MGR candidates: %+v %v", got, err)
	}
	got, err = store.LookupCandidates("tenant", []string{"old", "new"}, now)
	if err != nil || got.TokenID != "new" {
		t.Fatalf("newest candidate not selected: %+v %v", got, err)
	}
	if _, err := store.LookupCandidates("tenant", []string{"missing"}, now); !errors.Is(err, ErrInstanceTokenNotFound) {
		t.Fatalf("fallback outside candidates: %v", err)
	}
}
