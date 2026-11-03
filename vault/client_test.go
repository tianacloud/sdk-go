package vault

import "testing"

func TestSignatureGolden(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = 42
	}
	got := signature(key, "vault-test", "production/db", 100)
	const want = "04ReeK28HTm2Gpj5pH10mHEmJZfb0HdN679BOrOetsg="
	if got != want {
		t.Fatalf("signature: %s", got)
	}
}
