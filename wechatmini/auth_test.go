package wechatmini

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestAuth(t testing.TB) (*Authenticator, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	a, err := New(Config{AppID: "wx-test-app", AppSecret: "synthetic-secret",
		SigningKey: bytes.Repeat([]byte{7}, 32), SessionTTL: time.Hour,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			q := r.URL.Query()
			if r.Method != "GET" || r.URL.Host != "api.weixin.qq.com" || r.URL.Path != "/sns/jscode2session" ||
				q.Get("appid") != "wx-test-app" || q.Get("secret") != "synthetic-secret" || q.Get("grant_type") != "authorization_code" {
				t.Error("incorrect WeChat exchange")
			}
			body, _ := json.Marshal(map[string]any{"openid": "openid-" + q.Get("js_code"), "session_key": "synthetic-provider-key", "extra": true})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		})}})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1800000000, 0) }
	return a, calls
}

func TestLoginAndVerifiedContext(t *testing.T) {
	a, calls := newTestAuth(t)
	session, err := a.Login(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if session.Identity != (Identity{AppID: "wx-test-app", OpenID: "openid-alice"}) || session.ExpiresAt != 1800003600 {
		t.Fatal("wrong login identity or expiry")
	}
	encoded, _ := json.Marshal(session)
	if bytes.Contains(encoded, []byte("synthetic-secret")) || bytes.Contains(encoded, []byte("synthetic-provider-key")) {
		t.Fatal("provider secrets exposed")
	}
	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := FromContext(r.Context())
		if !ok || identity != session.Identity {
			t.Error("incorrect verified context")
		}
		json.NewEncoder(w).Encode(identity)
	}))
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "/business?user_id=someone-else", strings.NewReader(`{"user_id":"someone-else"}`))
		r.Header.Set(SessionHeader, session.Token)
		r.Header.Set("X-User-ID", "someone-else")
		r.Header.Set("Authorization", "Bearer synthetic-instance-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "openid-alice") {
			t.Fatal("business authentication failed")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("business requests performed a provider exchange")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unexpected identity")
	}
}

func TestSessionIntegrityExpiryAndApplicationScope(t *testing.T) {
	a, _ := newTestAuth(t)
	session, err := a.Login(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	payload, signature, _ := strings.Cut(session.Token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	tampered := base64.RawURLEncoding.EncodeToString(bytes.ReplaceAll(raw, []byte("openid-alice"), []byte("openid-bob"))) + "." + signature
	for _, token := range []string{"", "openid-alice", tampered, payload + ".AAAA", session.Token + ".suffix"} {
		if _, err := a.Verify(token); !errors.Is(err, ErrInvalidSession) {
			t.Fatal("invalid session accepted")
		}
	}
	b := *a
	b.appID = "other-mini-program"
	if _, err := b.Verify(session.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("wrong application accepted")
	}
	b = *a
	b.key = bytes.Repeat([]byte{9}, 32)
	if _, err := b.Verify(session.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("wrong signing key accepted")
	}
	a.now = func() time.Time { return time.Unix(session.ExpiresAt-1, 0) }
	if _, err := a.Verify(session.Token); err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(session.ExpiresAt, 0) }
	if _, err := a.Verify(session.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("expired session accepted")
	}
}

func TestMiddlewareRequiresSession(t *testing.T) {
	a, _ := newTestAuth(t)
	session, err := a.Login(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{nil, {"forged"}, {session.Token, session.Token}} {
		r := httptest.NewRequest("GET", "/me?user_id=alice", nil)
		r.Header.Set("Authorization", "Bearer synthetic-shared-instance-token")
		r.Header[http.CanonicalHeaderKey(SessionHeader)] = values
		w := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated business execution") })).ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("status %d", w.Code)
		}
	}
}

func TestConcurrentUsersKeepSeparateIdentities(t *testing.T) {
	a, _ := newTestAuth(t)
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := fmt.Sprintf("user-%d", i)
			session, err := a.Login(context.Background(), code)
			if err != nil {
				t.Error(err)
				return
			}
			identity, err := a.Verify(session.Token)
			if err != nil || identity.OpenID != "openid-"+code {
				t.Error("user identity mixed")
			}
		}()
	}
	wg.Wait()
}

func TestProviderFailuresDoNotIssueSessionsOrLeakSecrets(t *testing.T) {
	for name, body := range map[string]string{
		"rejected":         `{"errcode":40029,"errmsg":"sensitive-provider-detail"}`,
		"missing identity": `{"session_key":"sensitive-provider-detail"}`,
		"malformed":        `sensitive-provider-detail`,
		"oversized":        strings.Repeat("x", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := newTestAuth(t)
			a.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			session, err := a.Login(context.Background(), "sensitive-code")
			if err == nil || session.Token != "" {
				t.Fatal("failed exchange issued a session")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("error leaks provider material")
			}
			if name == "rejected" {
				var providerErr *ProviderError
				if !errors.As(err, &providerErr) || providerErr.Code != 40029 {
					t.Fatal("numeric provider error lost")
				}
			}
		})
	}
	a, _ := newTestAuth(t)
	a.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("sensitive-network-error") })
	if _, err := a.Login(context.Background(), "code"); err != ErrProviderUnavailable {
		t.Fatal("transport error not sanitized")
	}
	if _, err := a.Login(context.Background(), ""); err != ErrInvalidCode {
		t.Fatal("empty code accepted")
	}
}

func TestLoginCancellationAndRedirect(t *testing.T) {
	a, _ := newTestAuth(t)
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Login(ctx, "code"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	var calls int
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://other.example.test/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	if _, err := a.Login(context.Background(), "code"); err != ErrProviderUnavailable || calls != 1 {
		t.Fatal("redirect followed or accepted")
	}
}

func TestConfigurationOwnsSigningKey(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	client := &http.Client{}
	a, err := New(Config{AppID: "app", AppSecret: "secret", SigningKey: key, SessionTTL: time.Hour, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 0
	if a.key[0] != 7 || client.CheckRedirect != nil {
		t.Fatal("configuration ownership changed")
	}
	for _, c := range []Config{{}, {AppID: "app", AppSecret: "secret", SessionTTL: time.Hour}, {AppID: "app", AppSecret: "secret", SigningKey: key}} {
		if _, err := New(c); err == nil {
			t.Fatal("missing required configuration accepted")
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	a, _ := newTestAuth(b)
	session, err := a.Login(context.Background(), "benchmark")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := a.Verify(session.Token); err != nil {
			b.Fatal(err)
		}
	}
}
