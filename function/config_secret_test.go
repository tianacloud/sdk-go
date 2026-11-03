package function

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type secretTransport func(*http.Request) (*http.Response, error)

func (f secretTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSecretResolutionUsesParameterName(t *testing.T) {
	original := jobClient
	defer func() { jobClient = original }()
	calls := 0
	jobClient = &http.Client{Transport: secretTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "supervisor.tiana.com:80" || r.URL.Path != "/get_secret" || r.URL.Query().Get("key") != "PASSWORD" {
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"value":""}`)), Header: http.Header{}}, nil
	})}
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FUNCTION_CONFIG_FILE", path)
	if err := os.WriteFile(path, []byte(`{"PASSWORD":{"kind":"secret","value":"production/password"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadConfig()
	if err != nil || calls != 0 || c["PASSWORD"].Value != "production/password" {
		t.Fatal("ReadConfig resolved reference", err)
	}
	value, err := c.Get("PASSWORD")
	if err != nil || value != "" || calls != 1 {
		t.Fatal("empty secret was not preserved", err)
	}
}
func TestSecretErrorsRemainDistinct(t *testing.T) {
	original := jobClient
	defer func() { jobClient = original }()
	c := Config{"KEY": {Kind: "secret", Value: "reference"}}
	for _, status := range []int{404, 403, 503} {
		jobClient = &http.Client{Transport: secretTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("private backend text"))}, nil
		})}
		value, err := c.Get("KEY")
		if value != "" || err == nil || errors.Is(err, ErrNotExist) != (status == 404) || strings.Contains(err.Error(), "private backend text") {
			t.Fatalf("status %d: %q, %v", status, value, err)
		}
	}
}
