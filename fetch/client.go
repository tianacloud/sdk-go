// Package fetch provides the bounded TFQ1/TFS1 HTTP gateway transport.
// Bodies and Content-Encoding are passed through without decompression.
package fetch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	tiana "github.com/tianacloud/sdk-go"
)

const MaxBody int64 = 16 << 20
const MaxMetadata = 64 << 10
const mediaType = "application/vnd.tiana.fetch.v1"

var ErrProtocol = errors.New("invalid gateway fetch frame")
var ErrTransport = errors.New("gateway fetch transport failed; request outcome may be unknown")

type Config struct {
	Endpoint, Token, DialAddress, Port string
	RootCAs                            *x509.CertPool
	Timeout                            time.Duration
}

func (Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "fetch.Config([REDACTED])") }

type Client struct {
	origin    string
	token     string
	http      *http.Client
	transport *http.Transport
}

func (*Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "fetch.Client([REDACTED])") }

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Request struct {
	Method, PathQuery, RequestID string
	Headers                      []Header
	Body                         io.Reader
	BodyLength                   int64
}
type metadata struct {
	Version    int      `json:"metadata_version"`
	RequestID  string   `json:"request_id"`
	Protocol   string   `json:"protocol"`
	Method     string   `json:"method"`
	PathQuery  string   `json:"path_query"`
	Headers    []Header `json:"headers"`
	BodyLength int64    `json:"body_length"`
}
type Response struct {
	Status    int
	Header    http.Header
	Body      io.ReadCloser
	RequestID string
}
type Error struct {
	Status          int
	Code, RequestID string
}

func (e *Error) Error() string {
	return fmt.Sprintf("gateway fetch failed: status %d (%s)", e.Status, e.Code)
}

func NewClient(c Config) (*Client, error) {
	host, err := tiana.ParseEndpoint(c.Endpoint)
	if err != nil {
		return nil, errors.New("invalid fetch endpoint")
	}
	if c.Token != "" {
		if _, err := tiana.NewToken(c.Token); err != nil {
			return nil, errors.New("invalid fetch token")
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 90 * time.Second
	}
	if c.Timeout < 0 {
		return nil, errors.New("invalid fetch timeout")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host}
	if c.RootCAs != nil {
		tlsCfg.RootCAs = c.RootCAs.Clone()
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, DisableCompression: true, MaxIdleConns: 32, MaxConnsPerHost: 32, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: c.Timeout}
	if c.DialAddress != "" {
		h, p, e := net.SplitHostPort(c.DialAddress)
		port, portErr := strconv.Atoi(p)
		if e != nil || h == "" || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != p || strings.ContainsAny(h, "/@?# \r\n") {
			return nil, errors.New("invalid fetch dial address")
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, c.DialAddress)
		}
	}
	authority := host
	if c.Port != "" {
		port, e := strconv.Atoi(c.Port)
		if e != nil || port < 1 || port > 65535 || strconv.Itoa(port) != c.Port {
			return nil, errors.New("invalid fetch port")
		}
		authority = net.JoinHostPort(host, c.Port)
	}
	return &Client{origin: "https://" + authority, token: c.Token, transport: transport, http: &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.transport.CloseIdleConnections() }
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	if r.BodyLength < 0 || r.BodyLength > MaxBody || r.BodyLength > 0 && r.Body == nil {
		return nil, ErrProtocol
	}
	switch r.Method {
	case "GET", "HEAD":
		if r.BodyLength != 0 {
			return nil, ErrProtocol
		}
	case "PUT", "POST", "PATCH", "DELETE", "OPTIONS":
	default:
		return nil, ErrProtocol
	}
	parsed, e := url.ParseRequestURI(r.PathQuery)
	if e != nil || !strings.HasPrefix(r.PathQuery, "/") || strings.HasPrefix(r.PathQuery, "//") || parsed.IsAbs() || parsed.Fragment != "" || len(r.PathQuery) > 8192 || strings.ContainsAny(r.PathQuery, "\\\r\n") {
		return nil, ErrProtocol
	}
	if r.RequestID == "" {
		var id [18]byte
		if _, e := rand.Read(id[:]); e != nil {
			return nil, ErrTransport
		}
		r.RequestID = hex.EncodeToString(id[:])
	}
	if !validID(r.RequestID) || len(r.Headers) > 128 {
		return nil, ErrProtocol
	}
	for _, h := range r.Headers {
		if !validHeader(h) {
			return nil, ErrProtocol
		}
	}
	if r.Headers == nil {
		r.Headers = []Header{}
	}
	raw, e := canonicalJSON(metadata{1, r.RequestID, "tiana-http", r.Method, r.PathQuery, r.Headers, r.BodyLength})
	if e != nil || len(raw) > MaxMetadata {
		return nil, ErrProtocol
	}
	head := make([]byte, 10+len(raw))
	copy(head, "TFQ1")
	binary.BigEndian.PutUint32(head[6:10], uint32(len(raw)))
	copy(head[10:], raw)
	var body io.Reader = bytes.NewReader(head)
	if r.BodyLength > 0 {
		body = io.MultiReader(body, io.LimitReader(r.Body, r.BodyLength))
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/v1/fetch", body)
	if e != nil {
		return nil, ErrProtocol
	}
	req.ContentLength = int64(len(head)) + r.BodyLength
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Accept-Encoding", "identity")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, e := c.http.Do(req)
	if e != nil {
		return nil, ErrTransport
	}
	if res.StatusCode != 200 {
		defer res.Body.Close()
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, MaxMetadata)).Decode(&envelope)
		code := "FETCH_FAILED"
		switch envelope.Error.Code {
		case "ACTIVATION_RESOURCE_PRESSURE", "ACTIVATION_NO_IDLE_POD", "ACTIVATION_CAPACITY_UNAVAILABLE":
			code = envelope.Error.Code
		}
		if strings.HasPrefix(envelope.Error.Code, "FETCH_") && validID(envelope.Error.Code) {
			code = envelope.Error.Code
		}
		return nil, &Error{res.StatusCode, code, r.RequestID}
	}
	fail := func() (*Response, error) { res.Body.Close(); return nil, ErrProtocol }
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Type") != mediaType || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		return fail()
	}
	var frame [10]byte
	if _, e = io.ReadFull(res.Body, frame[:]); e != nil || string(frame[:4]) != "TFS1" || binary.BigEndian.Uint16(frame[4:6]) != 0 {
		return fail()
	}
	n := binary.BigEndian.Uint32(frame[6:10])
	if n == 0 || n > MaxMetadata {
		return fail()
	}
	raw = make([]byte, n)
	if _, e = io.ReadFull(res.Body, raw); e != nil {
		return fail()
	}
	var meta struct {
		Version    int      `json:"metadata_version"`
		RequestID  string   `json:"request_id"`
		Status     int      `json:"status"`
		StatusText string   `json:"status_text"`
		Headers    []Header `json:"headers"`
		BodyLength *int64   `json:"body_length"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&meta) != nil || d.Decode(new(any)) != io.EOF || meta.Version != 1 || meta.RequestID != r.RequestID || meta.Status < 200 || meta.Status > 599 || meta.Headers == nil || len(meta.Headers) > 128 || len(meta.StatusText) > 128 || !asciiStatusText(meta.StatusText) || meta.BodyLength != nil && (*meta.BodyLength < 0 || *meta.BodyLength > MaxBody) {
		return fail()
	}
	canonical, canonicalErr := canonicalJSON(meta)
	if canonicalErr != nil || !bytes.Equal(canonical, raw) {
		return fail()
	}
	if r.Method == "HEAD" || meta.Status == 204 || meta.Status == 205 || meta.Status == 304 {
		if meta.BodyLength == nil || *meta.BodyLength != 0 {
			return fail()
		}
	}
	headers := make(http.Header)
	for _, h := range meta.Headers {
		if !validHeader(h) && !(h.Name == "content-length" && validLength(h.Value)) {
			return fail()
		}
		if (h.Name == "content-length" || h.Name == "content-encoding") && len(headers.Values(h.Name)) > 0 {
			return fail()
		}
		headers.Add(h.Name, h.Value)
	}
	if length := headers.Get("Content-Length"); length != "" && r.Method != "HEAD" && meta.Status != 304 {
		declared, _ := strconv.ParseInt(length, 10, 64)
		if meta.BodyLength != nil && *meta.BodyLength != declared {
			return fail()
		}
	}
	responseBody := &boundedBody{body: res.Body, remaining: meta.BodyLength}
	if r.Method == "HEAD" || meta.Status == 204 || meta.Status == 205 || meta.Status == 304 {
		var probe [1]byte
		if n, err := responseBody.Read(probe[:]); n != 0 || err != io.EOF {
			return fail()
		}
	}
	return &Response{meta.Status, headers, responseBody, r.RequestID}, nil
}
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || i > 0 && strings.ContainsRune("._:-", rune(b))) {
			return false
		}
	}
	return true
}
func validHeader(h Header) bool {
	if len(h.Name) == 0 || len(h.Name) > 128 || len(h.Value) > 8192 || strings.ToLower(h.Name) != h.Name || strings.TrimSpace(h.Value) != h.Value {
		return false
	}
	for _, b := range []byte(h.Name) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))) {
			return false
		}
	}
	for _, b := range []byte(h.Value) {
		if b != '\t' && (b < 32 || b > 126) {
			return false
		}
	}
	switch h.Name {
	case "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "forwarded", "via", "expect":
		return false
	}
	if strings.HasPrefix(h.Name, "proxy-") || strings.HasPrefix(h.Name, "tiana-") || strings.HasPrefix(h.Name, "x-forwarded-") {
		return false
	}
	if h.Name == "authorization" && strings.HasPrefix(strings.ToLower(h.Value), "bearer tia_") {
		return false
	}
	return true
}

type boundedBody struct {
	body      io.ReadCloser
	remaining *int64
	count     int64
	done      bool
}

func (b *boundedBody) Close() error { return b.body.Close() }
func (b *boundedBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	cap := MaxBody - b.count
	if b.remaining != nil {
		cap = *b.remaining - b.count
	}
	if cap == 0 {
		var probe [1]byte
		n, e := b.body.Read(probe[:])
		b.done = true
		if n != 0 || e != io.EOF {
			return 0, ErrProtocol
		}
		return 0, io.EOF
	}
	if int64(len(p)) > cap {
		p = p[:cap]
	}
	n, e := b.body.Read(p)
	b.count += int64(n)
	if e == io.EOF {
		b.done = true
		if b.remaining != nil && b.count != *b.remaining {
			return n, ErrProtocol
		}
	}
	return n, e
}

func validLength(s string) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && n <= uint64(MaxBody) && strconv.FormatUint(n, 10) == s
}

func asciiStatusText(value string) bool {
	for _, b := range []byte(value) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
