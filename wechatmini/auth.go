// Package wechatmini authenticates application users through WeChat mini-program
// login. Its identities belong to the application, independently of Tiana accounts.
package wechatmini

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const SessionHeader = "X-App-Session"

var (
	ErrInvalidCode         = errors.New("wechatmini: login code is required")
	ErrProviderUnavailable = errors.New("wechatmini: WeChat login unavailable")
	ErrInvalidSession      = errors.New("wechatmini: invalid or expired application session")
)

// ProviderError contains only WeChat's numeric error code, never its response text.
type ProviderError struct{ Code int }

func (e *ProviderError) Error() string {
	return fmt.Sprintf("wechatmini: WeChat rejected login (%d)", e.Code)
}

// Identity identifies a user within one mini program. Applications can map this
// pair to their own business user ID. OpenID alone is not a cross-application ID.
type Identity struct {
	AppID  string `json:"app_id"`
	OpenID string `json:"open_id"`
}

type Session struct {
	Token     string   `json:"token"`
	Identity  Identity `json:"identity"`
	ExpiresAt int64    `json:"expires_at"`
}

// Config is supplied by server code. SigningKey must contain at least 32 random
// bytes, shared by executions that should accept the same application sessions.
type Config struct {
	AppID      string
	AppSecret  string
	SigningKey []byte
	SessionTTL time.Duration
	HTTPClient *http.Client
}

type Authenticator struct {
	appID     string
	appSecret string
	key       []byte
	ttl       time.Duration
	client    http.Client
	now       func() time.Time
}

func New(cfg Config) (*Authenticator, error) {
	if cfg.AppID == "" || cfg.AppSecret == "" {
		return nil, errors.New("wechatmini: AppID and AppSecret are required")
	}
	if len(cfg.SigningKey) < 32 {
		return nil, errors.New("wechatmini: signing key requires at least 32 random bytes")
	}
	if cfg.SessionTTL < time.Second {
		return nil, errors.New("wechatmini: session lifetime must be at least one second")
	}
	client := http.Client{Timeout: 10 * time.Second}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	// The exchange URL contains server credentials; never forward them on redirects.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Authenticator{appID: cfg.AppID, appSecret: cfg.AppSecret,
		key: append([]byte(nil), cfg.SigningKey...), ttl: cfg.SessionTTL,
		client: client, now: time.Now}, nil
}

// Login verifies a fresh wx.login code with WeChat before issuing an application
// session. It neither creates a Tiana account nor retries a consumed code.
func (a *Authenticator) Login(ctx context.Context, code string) (Session, error) {
	if code == "" {
		return Session{}, ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	query := url.Values{"appid": {a.appID}, "secret": {a.appSecret}, "js_code": {code}, "grant_type": {"authorization_code"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.weixin.qq.com/sns/jscode2session?"+query.Encode(), nil)
	if err != nil {
		return Session{}, ErrProviderUnavailable
	}
	response, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Session{}, ctx.Err()
		}
		return Session{}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Session{}, ErrProviderUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return Session{}, ErrProviderUnavailable
	}
	var result struct {
		OpenID    string `json:"openid"`
		ErrorCode int    `json:"errcode"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return Session{}, ErrProviderUnavailable
	}
	if result.ErrorCode != 0 {
		return Session{}, &ProviderError{Code: result.ErrorCode}
	}
	if result.OpenID == "" {
		return Session{}, ErrProviderUnavailable
	}
	identity := Identity{AppID: a.appID, OpenID: result.OpenID}
	expiresAt := a.now().Add(a.ttl).Unix()
	claims, err := json.Marshal(sessionClaims{Identity: identity, ExpiresAt: expiresAt})
	if err != nil {
		return Session{}, err
	}
	payload := base64.RawURLEncoding.EncodeToString(claims)
	token := payload + "." + base64.RawURLEncoding.EncodeToString(a.signature(payload))
	return Session{Token: token, Identity: identity, ExpiresAt: expiresAt}, nil
}

type sessionClaims struct {
	Identity  Identity `json:"identity"`
	ExpiresAt int64    `json:"expires_at"`
}

func (a *Authenticator) signature(payload string) []byte {
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte("wechatmini/session\x00"))
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// Verify authenticates a session locally. Sessions expire at ExpiresAt; they do
// not renew on use. Calling Login again creates a new session after WeChat proof.
func (a *Authenticator) Verify(token string) (Identity, error) {
	payload, encodedSignature, ok := strings.Cut(token, ".")
	if !ok {
		return Identity{}, ErrInvalidSession
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || !hmac.Equal(signature, a.signature(payload)) {
		return Identity{}, ErrInvalidSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Identity{}, ErrInvalidSession
	}
	var claims sessionClaims
	if json.Unmarshal(raw, &claims) != nil || claims.Identity.AppID != a.appID ||
		claims.Identity.OpenID == "" || a.now().Unix() >= claims.ExpiresAt {
		return Identity{}, ErrInvalidSession
	}
	return claims.Identity, nil
}

type identityKey struct{}

// FromContext returns the application identity verified by Middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

// Middleware verifies X-App-Session and attaches its identity to this request.
// Authorization remains available for the separate Tiana instance credential.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(SessionHeader)
		if len(values) != 1 {
			writeUnauthorized(w)
			return
		}
		identity, err := a.Verify(values[0])
		if err != nil {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	})
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":"APP_SESSION_REQUIRED"}`)
}
