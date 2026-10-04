package tiana

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is copied by NewClient. RootCAs replaces system roots when non-nil.
// DialAddress changes only the TCP destination; SNI/authority remain Endpoint.
type Config struct {
	Endpoint        string
	Token           *Token
	RootCAs         *x509.CertPool
	DialAddress     string
	UserAgent       string
	ConnectTimeout  time.Duration
	ResponseTimeout time.Duration
	MaxStreams      int
	// OnRequestID receives the connection identity before network I/O.
	// Calls may be concurrent; keep the callback brief. Panics are ignored.
	OnRequestID func(string)
}

func (Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "tiana.Config([REDACTED])") }

// Client shares one HTTP/2 connection across concurrent tunnels for one
// Endpoint, credential and trust configuration. Close releases all resources.
type Client struct {
	mu       sync.Mutex
	gate     chan struct{}
	cfg      Config
	tls      *tls.Config
	ctx      context.Context
	cancel   context.CancelFunc
	current  *session
	sessions []*session
	closed   bool
}

func (*Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "tiana.Client([REDACTED])") }

func NewClient(cfg Config) (*Client, error) {
	host, err := ParseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	cfg.Endpoint = host
	if cfg.Token != nil {
		token, err := NewToken(cfg.Token.value)
		if err != nil {
			return nil, err
		}
		cfg.Token = token
	}
	if cfg.DialAddress == "" {
		cfg.DialAddress = net.JoinHostPort(host, "443")
	}
	dialHost, port, err := net.SplitHostPort(cfg.DialAddress)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || dialHost == "" || strings.ContainsAny(dialHost, "/@?# \t\r\n") || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, failure(Configuration, "dial address must be host:port", false)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ResponseTimeout == 0 {
		cfg.ResponseTimeout = 60 * time.Second
	}
	if cfg.ConnectTimeout < 0 || cfg.ResponseTimeout < 0 {
		return nil, failure(Configuration, "timeouts must be positive", false)
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 32
	}
	if cfg.MaxStreams < 1 || cfg.MaxStreams > 256 {
		return nil, failure(Configuration, "MaxStreams must be between 1 and 256", false)
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "tiana-sdk-go/" + Version
	}
	if len(cfg.UserAgent) > 256 {
		return nil, failure(Configuration, "invalid User-Agent", false)
	}
	for _, b := range []byte(cfg.UserAgent) {
		if b < 32 || b > 126 {
			return nil, failure(Configuration, "invalid User-Agent", false)
		}
	}
	if cfg.RootCAs != nil {
		cfg.RootCAs = cfg.RootCAs.Clone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{cfg: cfg, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel,
		tls: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ServerName: host, RootCAs: cfg.RootCAs}}, nil
}

// Connect returns only after complete, validated 200 response headers.
// ctx governs both establishment and the returned tunnel's entire lifetime.
func (c *Client) Connect(ctx context.Context, profile Profile) (*Tunnel, error) {
	switch profile {
	case HranaHTTP, HranaWebSocket, MySQL, PostgreSQL, Git, TianaHTTP:
	default:
		return nil, failure(Configuration, "unsupported profile", false)
	}
	if err := ctx.Err(); err != nil {
		return nil, contextFailure(err, false)
	}
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, failure(Configuration, "request ID generation failed", false)
	}
	requestID := "req-" + base64.RawURLEncoding.EncodeToString(random[:])
	if c.cfg.OnRequestID != nil {
		func() {
			defer func() { _ = recover() }()
			c.cfg.OnRequestID(requestID)
		}()
	}
	s, err := c.getSession(ctx)
	if err != nil {
		var connectionError *Error
		if errors.As(err, &connectionError) {
			copy := *connectionError
			copy.RequestID = requestID
			return nil, &copy
		}
		return nil, err
	}
	t, err := s.startTunnel(ctx, profile, requestID)
	if err != nil {
		return nil, err
	}
	<-t.ready
	if ctx.Err() != nil {
		s.abort(t, contextFailure(ctx.Err(), false))
	}
	s.mu.Lock()
	err = t.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (c *Client) getSession(ctx context.Context) (*session, error) {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, contextFailure(ctx.Err(), false)
	case <-c.ctx.Done():
		return nil, failure(Closed, "client closed", false)
	}
	defer func() { <-c.gate }()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, failure(Closed, "client closed", false)
	}
	var live []*session
	for _, s := range c.sessions {
		s.mu.Lock()
		alive := s.err == nil
		s.mu.Unlock()
		if alive {
			live = append(live, s)
		}
	}
	c.sessions = live
	if s := c.current; s != nil {
		s.mu.Lock()
		usable := s.err == nil && !s.draining
		s.mu.Unlock()
		if usable {
			c.mu.Unlock()
			return s, nil
		}
	}
	if len(live) >= 2 {
		c.mu.Unlock()
		return nil, failure(Limit, "draining connection limit reached", false)
	}
	c.mu.Unlock()
	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.ConnectTimeout)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", c.cfg.DialAddress)
	if err != nil {
		if dialCtx.Err() != nil {
			return nil, contextFailure(dialCtx.Err(), false)
		}
		return nil, failure(TCP, "connection failed", false)
	}
	tlsConn := tls.Client(conn, c.tls)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = conn.Close()
		if dialCtx.Err() != nil {
			return nil, contextFailure(dialCtx.Err(), false)
		}
		return nil, failure(TLS, "certificate verification or handshake failed", false)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, failure(TLS, "ALPN h2 required", false)
	}
	s := newSession(tlsConn, c.cfg)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, failure(Closed, "client closed", false)
	}
	c.sessions = append(c.sessions, s)
	c.current = s
	c.mu.Unlock()
	s.start()
	select {
	case <-s.ready:
		s.mu.Lock()
		err = s.err
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return s, nil
	case <-dialCtx.Done():
		err = contextFailure(dialCtx.Err(), false)
		s.shutdown(err)
		return nil, err
	}
}

// Close cancels active tunnels and closes every physical connection. It is
// safe to call repeatedly or concurrently with Connect, Read and Write.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	sessions := append([]*session(nil), c.sessions...)
	c.mu.Unlock()
	for _, s := range sessions {
		s.shutdown(failure(Closed, "client closed", false))
	}
	for _, s := range sessions {
		<-s.stopped
	}
	return nil
}
