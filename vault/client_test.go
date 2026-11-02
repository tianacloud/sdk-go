package vault

import "testing"

func TestSignatureGolden(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 42
	}
	got := signature(key, "vault-test", "production/db", 100)
	const want = "A40O4oeaxvgKH6TrMC6NdL581K0wBlhib7oVsAyBxMw="
	if got != want {
		t.Fatalf("signature: %s", got)
	}
}
