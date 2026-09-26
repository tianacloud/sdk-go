package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	defaultPollInterval = 5 * time.Second
	accessTokenSkew     = 30 * time.Second
	maxResponseBytes    = 1 << 20
)

var (
	ErrAuthenticationRequired = errors.New("authentication required")
	ErrTransactionExpired     = errors.New("authentication transaction expired")
	ErrTransactionDenied      = errors.New("authentication transaction denied")
	ErrTransactionCompleted   = errors.New("authentication transaction completed")
)

// Config controls the control-plane client. Origin must identify the MGR
// origin; HTTPS is required except for literal loopback IPs/localhost. Its
// path, if any, is preserved for local reverse proxies.
type Config struct {
	Origin string
	// HTTPClient supplies transport, timeout and cookie policy. The client is
	// copied and CheckRedirect is overridden: MGR requests never follow redirects.
	HTTPClient     *http.Client
	Store          CredentialStore
	Output         io.Writer
	PollInterval   time.Duration
	Now            func() time.Time
	Sleep          func(context.Context, time.Duration) error
	Hostname       string
	Platform       string
	NonInteractive bool
	// InsecureTLS accepts untrusted MGR certificates for this client. It is
	// disabled by default and must be explicitly selected by the caller.
	InsecureTLS bool
	RootCAs     *x509.CertPool
	// OnRequestID receives each request identity before network I/O. Keep the callback brief.
	OnRequestID func(string)
}

type Client struct {
	origin         *url.URL
	http           *http.Client
	store          CredentialStore
	output         io.Writer
	pollInterval   time.Duration
	now            func() time.Time
	sleep          func(context.Context, time.Duration) error
	hostname       string
	platform       string
	nonInteractive bool
	credentialGate chan struct{}
	onRequestID    func(string)
}

func New(origin string) (*Client, error) {
	return NewWithConfig(Config{Origin: origin})
}

func NewWithConfig(config Config) (*Client, error) {
	origin := strings.TrimSpace(config.Origin)
	if origin == "" {
		return nil, errors.New("MGR origin is required")
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("MGR origin must be an HTTP(S) origin without credentials, query, or fragment")
	}
	if !secureAuthURL(parsed) {
		return nil, errors.New("MGR origin requires HTTPS except for loopback development hosts")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.RawPath != "" {
		parsed.RawPath = ""
	}
	if config.HTTPClient == nil {
		config.HTTPClient = newDefaultHTTPClient(config.InsecureTLS)
	}
	if config.RootCAs != nil {
		copyClient := *config.HTTPClient
		base := copyClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		transport, ok := base.(*http.Transport)
		if !ok {
			return nil, errors.New("custom CA requires an HTTP transport")
		}
		cloned := transport.Clone()
		cloned.TLSClientConfig = &tls.Config{RootCAs: config.RootCAs, MinVersion: tls.VersionTLS12}
		copyClient.Transport = cloned
		config.HTTPClient = &copyClient
	}
	// Credentials may be in the JSON body, not just Authorization. Never
	// replay them to a redirect target, even with a caller-provided client.
	copyClient := *config.HTTPClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	config.HTTPClient = &copyClient
	if config.Output == nil {
		config.Output = io.Discard
	}
	if config.PollInterval < 0 {
		return nil, errors.New("poll interval cannot be negative")
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Sleep == nil {
		config.Sleep = sleepContext
	}
	if config.Hostname == "" {
		config.Hostname, _ = os.Hostname()
		if config.Hostname == "" {
			config.Hostname = "unknown"
		}
	}
	if config.Platform == "" {
		config.Platform = runtime.GOOS
	}
	if config.Store == nil {
		config.Store, err = NewCredentialStore(parsed.String())
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		origin: parsed, http: config.HTTPClient, store: config.Store, output: config.Output,
		onRequestID:  config.OnRequestID,
		pollInterval: config.PollInterval, now: config.Now, sleep: config.Sleep,
		hostname: config.Hostname, platform: config.Platform, nonInteractive: config.NonInteractive, credentialGate: make(chan struct{}, 1),
	}, nil
}

func (c *Client) Origin() string {
	if c == nil || c.origin == nil {
		return ""
	}
	return c.origin.String()
}

// User is the stable account projection returned by MGR. Email may be empty
// for identities that do not expose one.
type User struct {
	ID          string `json:"user_id"`
	TenantID    string `json:"tenant_id,omitempty"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Username    string `json:"username,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// CurrentSession returns the authenticated principal and tenant identity used
// to scope local credential candidates.
func (c *Client) CurrentSession(ctx context.Context) (User, error) {
	user, err := c.Whoami(ctx)
	if err != nil {
		return User{}, err
	}
	if user.ID == "" || user.TenantID == "" {
		return User{}, errors.New("current session identity is incomplete")
	}
	return user, nil
}

type Credential struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         User      `json:"user"`
}

type tokenResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	AccountCreated bool   `json:"account_created"`
	User           User   `json:"user"`
}

type AuthTransaction struct {
	ID                      string        `json:"transaction_id"`
	ClientSecret            string        `json:"-"`
	UserCode                string        `json:"user_code"`
	VerificationURI         string        `json:"verification_uri"`
	VerificationURIComplete string        `json:"verification_uri_complete"`
	ExpiresIn               int           `json:"expires_in"`
	PollInterval            time.Duration `json:"poll_interval"`
	CreatedAt               time.Time     `json:"created_at"`
}

type transactionResponse struct {
	TransactionID           string `json:"transaction_id"`
	ClientSecret            string `json:"client_secret"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	PollInterval            int    `json:"poll_interval"`
}

type transactionCreateRequest struct {
	Purpose string         `json:"purpose"`
	Client  clientMetadata `json:"client"`
}

type clientMetadata struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
}

type BrowserAuthAction struct {
	Type            string `json:"type"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
}

// UserActionRequired is a transport-neutral representation future Agent/MCP
// callers can return without exposing the transaction's client secret.
type UserActionRequired struct {
	Code   string            `json:"error"`
	Action BrowserAuthAction `json:"action"`
}

func (e UserActionRequired) Error() string {
	return "user action required"
}

func (t AuthTransaction) BrowserAction() UserActionRequired {
	return UserActionRequired{
		Code: "user_action_required",
		Action: BrowserAuthAction{
			Type: "browser_auth", VerificationURI: t.VerificationURIComplete, ExpiresIn: t.ExpiresIn,
		},
	}
}

type PollResult struct {
	Status               string        `json:"status"`
	RetryAfter           time.Duration `json:"retry_after"`
	AuthorizationCode    string        `json:"-"`
	AuthorizationExpires int           `json:"authorization_expires_in"`
}

type pollResponse struct {
	requestID         string
	Status            string `json:"status"`
	RetryAfter        int    `json:"retry_after"`
	AuthorizationCode string `json:"authorization_code"`
	ExpiresIn         int    `json:"expires_in"`
}

type APIError struct {
	Status    int
	RequestID string
	// Code and recovery fields are peer-controlled structured metadata.
	Code string
	// Message is fixed HTTP status text, never the arbitrary peer message.
	Message           string
	RetryAfter        time.Duration
	OperationID       string
	CommandNotAfter   string
	SecretRecoverable bool
}

func (e *APIError) Error() string {
	if e == nil {
		return "MGR request failed"
	}
	if code := diagnosticCode(e.Code); code != "" {
		return fmt.Sprintf("MGR request failed (status %d, code %s)", e.Status, code)
	}
	return fmt.Sprintf("MGR request failed (status %d)", e.Status)
}

func (e APIError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }

func (c *Client) CreateAuthTransaction(ctx context.Context) (AuthTransaction, error) {
	if c == nil || c.origin == nil {
		return AuthTransaction{}, errors.New("auth client is not configured")
	}
	var response transactionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/transactions", transactionCreateRequest{
		Purpose: "cli_login",
		Client:  clientMetadata{Type: "cli", Name: "Tiana CLI", Hostname: c.hostname, Platform: c.platform},
	}, "", &response); err != nil {
		return AuthTransaction{}, err
	}
	if response.TransactionID == "" || response.ClientSecret == "" || response.UserCode == "" || response.VerificationURIComplete == "" || response.ExpiresIn <= 0 {
		return AuthTransaction{}, errors.New("MGR returned an incomplete authentication transaction")
	}
	if !safeBrowserURL(response.VerificationURIComplete) {
		return AuthTransaction{}, errors.New("MGR returned an unsafe verification URL")
	}
	interval := time.Duration(response.PollInterval) * time.Second
	if interval <= 0 {
		interval = c.pollInterval
	}
	return AuthTransaction{
		ID: response.TransactionID, ClientSecret: response.ClientSecret,
		UserCode: response.UserCode, VerificationURI: response.VerificationURI,
		VerificationURIComplete: response.VerificationURIComplete,
		ExpiresIn:               response.ExpiresIn, PollInterval: interval, CreatedAt: c.now(),
	}, nil
}

func (c *Client) PollAuthTransaction(ctx context.Context, transaction AuthTransaction) (PollResult, error) {
	if transaction.ID == "" || transaction.ClientSecret == "" {
		return PollResult{}, errors.New("authentication transaction is incomplete")
	}
	var response pollResponse
	path := "/api/v1/auth/transactions/" + url.PathEscape(transaction.ID) + "/poll"
	err := c.doJSON(ctx, http.MethodPost, path, struct {
		ClientSecret string `json:"client_secret"`
	}{transaction.ClientSecret}, "", &response)
	if err != nil {
		return PollResult{}, err
	}
	failure := func(cause error) error {
		return &requestError{cause: cause, RequestID: response.requestID, message: cause.Error()}
	}
	status := strings.ToLower(strings.TrimSpace(response.Status))
	if status == "" {
		return PollResult{}, failure(errors.New("MGR returned an empty authentication transaction status"))
	}
	result := PollResult{Status: status, RetryAfter: time.Duration(response.RetryAfter) * time.Second, AuthorizationCode: response.AuthorizationCode, AuthorizationExpires: response.ExpiresIn}
	switch status {
	case "pending", "authenticated":
		return result, nil
	case "approved":
		if result.AuthorizationCode == "" {
			return PollResult{}, failure(errors.New("MGR approved authentication without an authorization code"))
		}
		return result, nil
	case "expired":
		return result, failure(ErrTransactionExpired)
	case "denied":
		return result, failure(ErrTransactionDenied)
	case "completed":
		return result, failure(ErrTransactionCompleted)
	default:
		return PollResult{}, failure(errors.New("MGR returned an unknown authentication transaction status"))
	}
}

func (c *Client) Login(ctx context.Context) (Credential, error) {
	transaction, err := c.CreateAuthTransaction(ctx)
	if err != nil {
		return Credential{}, err
	}
	fmt.Fprintln(c.output, "Open:")
	fmt.Fprintln(c.output, transaction.VerificationURIComplete)
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "Waiting for authentication...")
	deadline := transaction.CreatedAt.Add(time.Duration(transaction.ExpiresIn) * time.Second)
	loginContext, cancel := context.WithTimeout(ctx, time.Duration(transaction.ExpiresIn)*time.Second)
	defer cancel()
	for {
		if !c.now().Before(deadline) {
			return Credential{}, ErrTransactionExpired
		}
		result, pollErr := c.PollAuthTransaction(loginContext, transaction)
		if errors.Is(pollErr, context.DeadlineExceeded) {
			return Credential{}, ErrTransactionExpired
		}
		if errors.Is(pollErr, ErrTransactionExpired) || errors.Is(pollErr, ErrTransactionDenied) || errors.Is(pollErr, ErrTransactionCompleted) {
			return Credential{}, pollErr
		}
		if pollErr != nil {
			var apiErr *APIError
			if !errors.As(pollErr, &apiErr) || apiErr.RetryAfter <= 0 {
				return Credential{}, pollErr
			}
			if err := c.wait(ctx, apiErr.RetryAfter, deadline); err != nil {
				return Credential{}, err
			}
			continue
		}
		if result.Status != "approved" {
			interval := result.RetryAfter
			if interval <= 0 {
				interval = transaction.PollInterval
			}
			if err := c.wait(ctx, interval, deadline); err != nil {
				return Credential{}, err
			}
			continue
		}
		credential, accountCreated, err := c.exchangeAuthorizationCode(loginContext, transaction, result.AuthorizationCode)
		if err != nil {
			return Credential{}, err
		}
		if err := c.withCredentialLock(loginContext, func(store CredentialStore) error { return store.Save(credential) }); err != nil {
			return Credential{}, err
		}
		if accountCreated {
			fmt.Fprintln(c.output, "✓ Account created")
		}
		fmt.Fprintf(c.output, "✓ Signed in as %s\n", safeUserLabel(userLabel(credential.User)))
		return credential, nil
	}
}

func (c *Client) exchangeAuthorizationCode(ctx context.Context, transaction AuthTransaction, authorizationCode string) (Credential, bool, error) {
	var response tokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/token", struct {
		GrantType         string `json:"grant_type"`
		TransactionID     string `json:"transaction_id"`
		AuthorizationCode string `json:"authorization_code"`
		ClientSecret      string `json:"client_secret"`
	}{"auth_transaction", transaction.ID, authorizationCode, transaction.ClientSecret}, "", &response)
	if err != nil {
		return Credential{}, false, err
	}
	credential, err := credentialFromToken(response, c.now(), Credential{})
	if err != nil {
		return Credential{}, false, err
	}
	return credential, response.AccountCreated, nil
}

func (c *Client) LoadCredential() (Credential, error) {
	return c.loadCredential(context.Background())
}
func (c *Client) loadCredential(ctx context.Context) (Credential, error) {
	if c == nil || c.store == nil {
		return Credential{}, ErrCredentialNotFound
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	// FileStore reads are already atomic, bounded and side-effect free. Do not
	// create a directory/lock for a read of missing credentials.
	if _, ok := c.store.(*FileStore); ok {
		return c.store.Load()
	}
	var credential Credential
	err := c.withCredentialLock(ctx, func(store CredentialStore) error {
		var err error
		credential, err = store.Load()
		return err
	})
	return credential, err
}

func (c *Client) EnsureCredential(ctx context.Context) (Credential, error) {
	credential, err := c.loadCredential(ctx)
	if errors.Is(err, ErrCredentialNotFound) {
		return Credential{}, ErrAuthenticationRequired
	}
	if err != nil {
		return Credential{}, err
	}
	if credential.AccessToken == "" || credential.RefreshToken == "" {
		return Credential{}, ErrAuthenticationRequired
	}
	if credential.ExpiresAt.After(c.now().Add(accessTokenSkew)) {
		return credential, nil
	}
	return c.refresh(ctx, credential)
}

func (c *Client) Refresh(ctx context.Context) (Credential, error) {
	credential, err := c.loadCredential(ctx)
	if errors.Is(err, ErrCredentialNotFound) {
		return Credential{}, ErrAuthenticationRequired
	}
	if err != nil {
		return Credential{}, err
	}
	return c.refresh(ctx, credential)
}

// withCredentialLock serializes this client's custom store or, for FileStore,
// all cooperating processes sharing the account file. The callback uses an
// unlocked adapter so refresh can atomically reload/rotate/persist.
func (c *Client) withCredentialLock(ctx context.Context, fn func(CredentialStore) error) error {
	if store, ok := c.store.(*FileStore); ok {
		return store.withLock(ctx, fn)
	}
	wait, cancel := context.WithTimeout(ctx, lockWaitTimeout)
	defer cancel()
	if err := wait.Err(); err != nil {
		return err
	}
	select {
	case c.credentialGate <- struct{}{}:
		defer func() { <-c.credentialGate }()
	case <-wait.Done():
		return wait.Err()
	}
	return fn(c.store)
}

func (c *Client) refresh(ctx context.Context, previous Credential) (Credential, error) {
	var credential Credential
	err := c.withCredentialLock(ctx, func(store CredentialStore) error {
		current, err := store.Load()
		if errors.Is(err, ErrCredentialNotFound) {
			return ErrAuthenticationRequired
		}
		if err != nil {
			return err
		}
		// Another process may already have rotated the credential we loaded before
		// waiting. Reuse that replacement instead of presenting the revoked token.
		if !sameCredentialVersion(current, previous) && current.ExpiresAt.After(c.now().Add(accessTokenSkew)) {
			credential = current
			return nil
		}
		previous = current
		var response tokenResponse
		err = c.doJSON(ctx, http.MethodPost, "/api/v1/auth/refresh", struct {
			RefreshToken string `json:"refresh_token"`
		}{previous.RefreshToken}, "", &response)
		if err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.Code == "invalid_grant" {
				// Also compare for custom stores. Their cross-client atomicity still
				// belongs to the caller, but never deliberately delete a newer snapshot.
				latest, loadErr := store.Load()
				if errors.Is(loadErr, ErrCredentialNotFound) {
					return ErrAuthenticationRequired
				}
				if loadErr != nil {
					return loadErr
				}
				if !sameCredentialVersion(latest, previous) {
					credential = latest
					return nil
				}
				if err := store.Delete(); err != nil {
					return err
				}
				return ErrAuthenticationRequired
			}
			return err
		}
		credential, err = credentialFromToken(response, c.now(), previous)
		if err != nil {
			return err
		}
		return store.Save(credential)
	})
	return credential, err
}
func sameCredentialVersion(a, b Credential) bool {
	return a.AccessToken == b.AccessToken && a.RefreshToken == b.RefreshToken && a.ExpiresAt.Equal(b.ExpiresAt)
}

func (c *Client) Whoami(ctx context.Context) (User, error) {
	credential, err := c.EnsureCredential(ctx)
	if err != nil {
		return User{}, err
	}
	var response struct {
		User User `json:"user"`
	}
	err = c.doJSON(ctx, http.MethodGet, "/api/v1/auth/transactions/whoami", nil, credential.AccessToken, &response)
	if err == nil {
		return response.User, nil
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		return User{}, err
	}
	credential, err = c.refresh(ctx, credential)
	if err != nil {
		return User{}, err
	}
	if err = c.doJSON(ctx, http.MethodGet, "/api/v1/auth/transactions/whoami", nil, credential.AccessToken, &response); err != nil {
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return User{}, ErrAuthenticationRequired
		}
		return User{}, err
	}
	return response.User, nil
}

func (c *Client) Logout(ctx context.Context) error {
	if c == nil || c.store == nil {
		return nil
	}
	return c.withCredentialLock(ctx, func(store CredentialStore) error {
		credential, err := store.Load()
		if errors.Is(err, ErrCredentialNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		requestErr := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/transactions/logout", struct {
			RefreshToken string `json:"refresh_token"`
		}{credential.RefreshToken}, "", nil)
		deleteErr := store.Delete()
		if requestErr != nil {
			return requestErr
		}
		return deleteErr
	})
}

func credentialFromToken(response tokenResponse, now time.Time, previous Credential) (Credential, error) {
	if response.AccessToken == "" || response.RefreshToken == "" || response.ExpiresIn <= 0 {
		return Credential{}, errors.New("MGR returned incomplete credentials")
	}
	tokenType := response.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	user := response.User
	if user.ID == "" && previous.User.ID != "" {
		user = previous.User
	}
	return Credential{AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, TokenType: tokenType, ExpiresAt: now.Add(time.Duration(response.ExpiresIn) * time.Second), User: user}, nil
}

func userLabel(user User) string {
	if user.Email != "" {
		return user.Email
	}
	if user.DisplayName != "" {
		return user.DisplayName
	}
	if user.Username != "" {
		return user.Username
	}
	if user.ID != "" {
		return user.ID
	}
	return "your Tiana account"
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload interface{}, accessToken string, result interface{}) error {
	return c.doJSONWithHeaders(ctx, method, path, payload, accessToken, nil, result)
}

// newDefaultHTTPClient returns the process default client, or one that accepts
// untrusted server certificates when a build enables insecure TLS.
func newDefaultHTTPClient(insecure bool) *http.Client {
	if !insecure {
		return http.DefaultClient
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: transport}
}

func (c *Client) doJSONWithHeaders(ctx context.Context, method, path string, payload interface{}, accessToken string, headers map[string]string, result interface{}) error {
	_, err := c.doJSONWithHeadersStatus(ctx, method, path, payload, accessToken, headers, result)
	return err
}

// doJSONWithHeadersStatus performs one MGR request and also reports the HTTP
// status so callers can distinguish a first delivery (201) from an idempotent
// replay (200) whose response carries no secret.
func (c *Client) doJSONWithHeadersStatus(ctx context.Context, method, path string, payload interface{}, accessToken string, headers map[string]string, result interface{}) (int, error) {
	if c == nil || c.origin == nil || c.http == nil {
		return 0, errors.New("auth client is not configured")
	}
	var body io.Reader
	if payload != nil {
		contents, err := json.Marshal(payload)
		if err != nil {
			return 0, errors.New("encode MGR request")
		}
		body = bytes.NewReader(contents)
	}
	requestURL := *c.origin
	basePath := strings.TrimRight(requestURL.Path, "/")
	requestPath, rawQuery, _ := strings.Cut(path, "?")
	requestURL.Path = basePath + requestPath
	requestURL.RawPath = ""
	requestURL.RawQuery = rawQuery
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return 0, errors.New("create MGR request")
	}
	requestID, _ := ctx.Value(requestIdentityKey{}).(string)
	if requestID == "" {
		var requestIdentity [18]byte
		if _, err := rand.Read(requestIdentity[:]); err != nil {
			return 0, errors.New("generate MGR request ID")
		}
		requestID = "req-" + base64.RawURLEncoding.EncodeToString(requestIdentity[:])
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("X-Request-ID", requestID)
	if c.onRequestID != nil {
		func() {
			defer func() { _ = recover() }()
			c.onRequestID(requestID)
		}()
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, &requestError{cause: err, RequestID: requestID}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		apiError := parseAPIError(response).(*APIError)
		apiError.RequestID = requestID
		return response.StatusCode, apiError
	}
	if result == nil || response.StatusCode == http.StatusNoContent {
		return response.StatusCode, nil
	}
	if poll, ok := result.(*pollResponse); ok {
		poll.requestID = requestID
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(result); err != nil {
		return response.StatusCode, &requestError{cause: errors.New("MGR returned invalid JSON"), RequestID: requestID, message: "MGR returned invalid JSON"}
	}
	return response.StatusCode, nil
}

// Transport parsers can include peer-controlled bytes in their errors. Keep
// the cause for errors.Is/As, but do not render it in ordinary diagnostics.
type requestError struct {
	cause     error
	RequestID string
	message   string
}

func (e *requestError) Error() string {
	if e.message != "" {
		return e.message
	}
	return "MGR request failed"
}
func (e *requestError) Unwrap() error             { return e.cause }
func (e requestError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }

// RequestIDOf returns the MGR request identity associated with an error.
func RequestIDOf(err error) string {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return apiError.RequestID
	}
	var transportError *requestError
	if errors.As(err, &transportError) {
		return transportError.RequestID
	}
	return ""
}

// parseAPIError accepts both the nested product/lifecycle error body and the
// flat authentication error body. The nested form carries the operation and
// deadline needed to resume a write whose commit result is unknown.
func parseAPIError(response *http.Response) error {
	var body struct {
		Error      json.RawMessage `json:"error"`
		RetryAfter int             `json:"retry_after"`
	}
	contents, _ := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	_ = json.Unmarshal(contents, &body)
	code := ""
	message := ""
	operationID := ""
	commandNotAfter := ""
	secretRecoverable := false
	if len(body.Error) > 0 {
		var flat string
		if err := json.Unmarshal(body.Error, &flat); err == nil {
			code = safeErrorCode(flat)
		} else {
			var nested struct {
				Code              string `json:"code"`
				Message           string `json:"message"`
				OperationID       string `json:"operation_id"`
				CommandNotAfter   string `json:"command_not_after"`
				SecretRecoverable bool   `json:"secret_recoverable"`
			}
			if err := json.Unmarshal(body.Error, &nested); err == nil {
				code = safeErrorCode(nested.Code)
				// Peer messages may contain reflected credentials or terminal controls.
				message = http.StatusText(response.StatusCode)
				operationID = nested.OperationID
				commandNotAfter = nested.CommandNotAfter
				secretRecoverable = nested.SecretRecoverable
			}
		}
	}
	if response.Header.Get("Retry-After") != "" {
		if headerRetryAfter, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil {
			body.RetryAfter = headerRetryAfter
		}
	}
	return &APIError{
		Status: response.StatusCode, Code: code, Message: message,
		RetryAfter:        time.Duration(max(0, body.RetryAfter)) * time.Second,
		OperationID:       operationID,
		CommandNotAfter:   commandNotAfter,
		SecretRecoverable: secretRecoverable,
	}
}

// Only fixed protocol literals are safe to print. Code remains available as
// structured metadata for forwards-compatible recovery logic.
func diagnosticCode(code string) string {
	switch code {
	case "invalid_grant", "invalid_request", "unauthorized", "forbidden", "rate_limited", "COMMIT_STATUS_UNKNOWN", "INSTANCE_NOT_FOUND", "INVALID_INSTANCE_ID":
		return code
	default:
		return ""
	}
}

func secureAuthURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func safeBrowserURL(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	u, err := url.Parse(value)
	return err == nil && u.Host != "" && u.User == nil && secureAuthURL(u)
}
func safeUserLabel(value string) string {
	var b strings.Builder
	for _, r := range value {
		if b.Len() >= 256 {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func safeErrorCode(value string) string {
	if len(value) > 64 || value == "" {
		return ""
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '.' {
			return ""
		}
	}
	return value
}

func (c *Client) wait(ctx context.Context, duration time.Duration, deadline time.Time) error {
	if duration <= 0 {
		return nil
	}
	remaining := deadline.Sub(c.now())
	if remaining <= 0 {
		return ErrTransactionExpired
	}
	if duration > remaining {
		duration = remaining
	}
	return c.sleep(ctx, duration)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
