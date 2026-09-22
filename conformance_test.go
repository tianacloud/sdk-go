package tiana

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPublicConnectArtifacts(t *testing.T) {
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile("conformance/v1/" + path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	manifest := read("manifest.json")
	var m struct {
		Identity  string `json:"contract_identity"`
		Digest    string `json:"manifest_sha256"`
		Artifacts map[string]struct {
			Path   string `json:"path"`
			Digest string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.Identity != "tiana.sdk-go.connect-v1.public.1" || len(m.Digest) != 64 {
		t.Fatal("wrong public distribution")
	}
	check := func(data []byte, want string) {
		t.Helper()
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("conformance artifact digest mismatch")
		}
	}
	check(bytes.Replace(manifest, []byte(m.Digest), []byte(strings.Repeat("0", 64)), 1), m.Digest)
	for _, key := range []string{"public-connect-authority", "public-connect-protocol", "consumer-provenance"} {
		artifact, ok := m.Artifacts[key]
		if !ok {
			t.Fatal("missing artifact", key)
		}
		check(read(artifact.Path), artifact.Digest)
	}
	var authority struct {
		Form  string `json:"endpoint_form"`
		Port  int    `json:"default_port"`
		Cases []struct {
			Input    string `json:"input"`
			Hostname string `json:"hostname"`
			Invalid  bool   `json:"invalid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(read("fixtures/gateway/public-connect-authority-v1.json"), &authority); err != nil {
		t.Fatal(err)
	}
	if authority.Form != "deployment_hostname" || authority.Port != 443 || len(authority.Cases) == 0 {
		t.Fatal("invalid public authority fixture")
	}
	for _, tc := range authority.Cases {
		host, err := ParseEndpoint(tc.Input)
		if tc.Invalid {
			if err == nil {
				t.Errorf("accepted invalid fixture input %q", tc.Input)
			}
		} else if err != nil || host != tc.Hostname {
			t.Errorf("fixture %q: host=%q err=%v", tc.Input, host, err)
		}
	}
}

func TestEndpointAndTokenInput(t *testing.T) {
	for _, input := range []string{testEndpoint + testEndpointSuffix, strings.ToUpper(testEndpoint + testEndpointSuffix)} {
		host, err := ParseEndpoint(input)
		if err != nil || host != testEndpoint+testEndpointSuffix {
			t.Fatal("endpoint normalization", err)
		}
	}
	for _, input := range []string{testEndpoint, "https://" + testEndpoint + testEndpointSuffix, testEndpoint + testEndpointSuffix + ":443", "ep-81j5c9m7q2v8x4k6n3r0t1w2yz", testEndpoint + " "} {
		if _, err := ParseEndpoint(input); err == nil {
			t.Fatal("accepted invalid endpoint")
		}
	}
	for _, domain := range []string{"db.a.example.test", "db.b.example.test"} {
		want := testEndpoint + "." + domain
		if host, err := ParseEndpoint(strings.ToUpper(want)); err != nil || host != want {
			t.Fatalf("deployment endpoint = %q, %v", host, err)
		}
	}
	for _, input := range []string{"x", "group-secret-with-arbitrary-prefix-and-length", strings.Repeat("z", 257)} {
		token, err := NewToken(input)
		if err != nil || token.value != input {
			t.Fatalf("opaque token %q changed or rejected: %v", input, err)
		}
	}
	for _, input := range []string{"", "line\nbreak", "line\rbreak"} {
		if _, err := NewToken(input); err == nil {
			t.Fatalf("accepted token outside HTTP header boundary %q", input)
		}
	}
}
