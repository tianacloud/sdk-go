package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func legacyTokenFixture(expiry string) []byte {
	return []byte(fmt.Sprintf(`{"tokens":{"https://mgr.example|tenant|instance|old":{"origin":"https://mgr.example","tenant_id":"tenant","instance_id":"instance","endpoint_id":"endpoint","token_id":"old","token":"synthetic-old-token","expires_at":%s,"saved_at":"2026-01-01T00:00:00Z"}}}`, expiry))
}

func TestLegacyInstanceTokenExpiryLookup(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, raw string
		want      int64
		usable    bool
	}{
		{"timestamp", `"2026-01-01T00:01:00.999Z"`, 1767225660, true},
		{"offset", `"2026-01-01T01:01:00+01:00"`, 1767225660, true},
		{"never", `"9999-12-31T23:59:59.999Z"`, -1, true},
		{"expired", `"2025-12-31T23:59:00Z"`, 1767225540, false},
		{"skew", `"2026-01-01T00:00:30.999Z"`, 1767225630, false},
		{"integer", `1767225660`, 1767225660, true},
		{"integer-never", `-1`, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tokens.json")
			before := legacyTokenFixture(tc.raw)
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			s := NewFileInstanceTokenStore(path, "https://mgr.example")
			got, err := s.Lookup("instance", "endpoint", now)
			if tc.usable {
				if err != nil || got.ExpiresAt != tc.want || got.Token != "synthetic-old-token" {
					t.Fatalf("legacy lookup failed: %v", err)
				}
			} else if !errors.Is(err, ErrInstanceTokenNotFound) {
				t.Fatalf("expired token lookup: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("lookup modified store")
			}
		})
	}
}

func TestSavePreservesLegacyInstanceTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, legacyTokenFixture(`"9999-12-31T23:59:59.999Z"`), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewFileInstanceTokenStore(path, "https://other.example")
	if _, err := s.Save(InstanceTokenCredential{TenantID: "tenant", InstanceID: "other", EndpointID: "endpoint", TokenID: "new", Token: "synthetic-new-token", ExpiresAt: -1}); err != nil {
		t.Fatal(err)
	}
	old := NewFileInstanceTokenStore(path, "https://mgr.example")
	got, err := old.Lookup("instance", "endpoint", time.Now())
	if err != nil || got.Token != "synthetic-old-token" || got.ExpiresAt != -1 {
		t.Fatalf("old token lost: %v", err)
	}
	got, err = s.Lookup("other", "endpoint", time.Now())
	if err != nil || got.Token != "synthetic-new-token" {
		t.Fatalf("new token missing: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Tokens map[string]struct {
			ExpiresAt json.RawMessage `json:"expires_at"`
		} `json:"tokens"`
	}
	if json.Unmarshal(contents, &file) != nil || len(file.Tokens) != 2 {
		t.Fatal("invalid saved store")
	}
	for _, value := range file.Tokens {
		if string(value.ExpiresAt) != "-1" {
			t.Fatal("save did not canonicalize expiry")
		}
	}
}

func TestMalformedLegacyExpiryDoesNotOverwriteStore(t *testing.T) {
	for _, expiry := range []string{`"secret-invalid-date"`, `""`, `"-1"`, `true`, `{}`, `1.25`, `"1969-12-31T23:59:59Z"`} {
		t.Run(expiry, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tokens.json")
			before := legacyTokenFixture(expiry)
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			s := NewFileInstanceTokenStore(path, "https://mgr.example")
			if _, err := s.Lookup("instance", "endpoint", time.Now()); err == nil {
				t.Fatal("accepted malformed/unsafe expiry")
			}
			if _, err := s.Save(InstanceTokenCredential{TenantID: "tenant", InstanceID: "other", TokenID: "new", Token: "synthetic", ExpiresAt: -1}); err == nil {
				t.Fatal("overwrote invalid store")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid store changed")
			}
		})
	}
}
