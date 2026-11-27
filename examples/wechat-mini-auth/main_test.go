package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/wechatmini"
)

type providerTransport func(*http.Request) (*http.Response, error)

func (f providerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDemoLoginAndBusinessIdentity(t *testing.T) {
	auth, err := wechatmini.New(wechatmini.Config{AppID: "wx-demo", AppSecret: "synthetic-secret", SigningKey: bytes.Repeat([]byte{1}, 32), SessionTTL: time.Hour,
		HTTPClient: &http.Client{Transport: providerTransport(func(r *http.Request) (*http.Response, error) {
			code := r.URL.Query().Get("js_code")
			body := `{"errcode":40029,"errmsg":"untrusted upstream detail"}`
			if code == "alice" || code == "bob" {
				b, _ := json.Marshal(map[string]string{"openid": "openid-" + code, "session_key": "synthetic-private-key"})
				body = string(b)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newHandler(auth))
	defer server.Close()
	call := func(method, path, body, session string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(context.Background(), method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer same-instance-token")
		if session != "" {
			r.Header.Set(wechatmini.SessionHeader, session)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	if status, _ := call("GET", "/health", "", ""); status != 200 {
		t.Fatal(status)
	}
	if status, _ := call("GET", "/me?user_id=alice", "", ""); status != 401 {
		t.Fatal("missing session accepted")
	}
	if status, body := call("POST", "/auth/login", `{"code":"invalid"}`, ""); status != 401 || bytes.Contains(body, []byte("untrusted")) {
		t.Fatal("provider failure not handled")
	}
	for _, name := range []string{"alice", "bob"} {
		status, body := call("POST", "/auth/login", `{"code":"`+name+`"}`, "")
		if status != 200 {
			t.Fatal(status)
		}
		var session wechatmini.Session
		if json.Unmarshal(body, &session) != nil {
			t.Fatal("invalid login JSON")
		}
		status, body = call("POST", "/greet", `{"message":"hello","user_id":"someone-else","open_id":"someone-else"}`, session.Token)
		var reply struct {
			Identity wechatmini.Identity `json:"identity"`
			Message  string              `json:"message"`
		}
		if status != 200 || json.Unmarshal(body, &reply) != nil || reply.Identity.OpenID != "openid-"+name || reply.Message != "hello" {
			t.Fatal("business user identity lost")
		}
		parts := strings.Split(session.Token, ".")
		parts[1] = "AAAA"
		if status, _ := call("GET", "/me", "", strings.Join(parts, ".")); status != 401 {
			t.Fatal("tampered session accepted")
		}
	}
}
