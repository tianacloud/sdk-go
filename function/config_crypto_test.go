package function

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncodedConfigAndLocalPlain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FUNCTION_CONFIG_FILE", path)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("FUNCTION_CONFIG_SECRET_KEY", base64.StdEncoding.EncodeToString(key))
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	encode := func(value string) string {
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(value), nil))
	}
	write := func(kind, value string) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"SECRET": map[string]string{"kind": kind, "value": value}, "MESSAGE": map[string]string{"kind": "plain", "value": "hello"}})
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "中文\n\"\\值", "updated"} {
		write("encoded", encode(value))
		config, err := ReadConfig()
		if err != nil || config["SECRET"] != value || config["MESSAGE"] != "hello" {
			t.Fatal("decode failed", err)
		}
	}
	ciphertext := encode("secret")
	write("encoded", ciphertext)
	for _, badKey := range []string{"", "bad", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		t.Setenv("FUNCTION_CONFIG_SECRET_KEY", badKey)
		if _, err := ReadConfig(); err == nil {
			t.Fatal("key error hidden by cache")
		}
	}
	t.Setenv("FUNCTION_CONFIG_SECRET_KEY", base64.StdEncoding.EncodeToString(key))
	bytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	bytes[len(bytes)-1] ^= 1
	write("encoded", base64.StdEncoding.EncodeToString(bytes))
	if _, err := ReadConfig(); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	write("plain_secret", "secret")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("unsupported file kind accepted")
	}
	t.Setenv("FUNCTION_CONFIG_SECRET_KEY", "")
	write("plain", "local")
	if config, err := ReadConfig(); err != nil || config["SECRET"] != "local" {
		t.Fatal("local plain requires key", err)
	}
}
