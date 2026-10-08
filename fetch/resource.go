package fetch

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	tiana "github.com/tianacloud/sdk-go"
)

// ResourceClient sends native HTTP over an opaque CONNECT stream (channel 0).
// It never uses TFQ1, changes Content-Encoding, follows redirects or retries.
// Publication uses Client instead: tiana-http Fetch selects channel 1.
type ResourceClient struct {
	native  *tiana.Client
	timeout time.Duration
}

func NewResourceClient(c Config) (*ResourceClient, error) {
	if c.Port != "" && c.Port != "443" && c.DialAddress == "" {
		host, err := tiana.ParseEndpoint(c.Endpoint)
		if err != nil {
			return nil, errors.New("invalid resource endpoint")
		}
		c.DialAddress = host + ":" + c.Port
	}
	var token *tiana.Token
	var err error
	if c.Token != "" {
		token, err = tiana.NewToken(c.Token)
		if err != nil {
			return nil, errors.New("invalid resource token")
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < 0 {
		return nil, errors.New("invalid resource timeout")
	}
	native, err := tiana.NewClient(tiana.Config{Endpoint: c.Endpoint, Token: token, RootCAs: c.RootCAs, DialAddress: c.DialAddress, ResponseTimeout: c.Timeout})
	if err != nil {
		return nil, err
	}
	return &ResourceClient{native: native, timeout: c.Timeout}, nil
}
func (c *ResourceClient) Close() { c.native.Close() }
func (c *ResourceClient) Do(ctx context.Context, r Request) (*Response, error) {
	if (r.Method != "GET" && r.Method != "HEAD") || r.BodyLength != 0 || r.Body != nil || len(r.Headers) > 128 {
		return nil, ErrProtocol
	}
	parsed, err := url.ParseRequestURI(r.PathQuery)
	if err != nil || !strings.HasPrefix(r.PathQuery, "/") || strings.HasPrefix(r.PathQuery, "//") || parsed.IsAbs() || parsed.Fragment != "" || len(r.PathQuery) > 8192 || strings.ContainsAny(r.PathQuery, "\\\r\n") {
		return nil, ErrProtocol
	}
	req, err := http.NewRequest(r.Method, "http://app.invalid"+r.PathQuery, nil)
	if err != nil {
		return nil, ErrProtocol
	}
	for _, h := range r.Headers {
		if !validHeader(h) {
			return nil, ErrProtocol
		}
		req.Header.Add(h.Name, h.Value)
	}
	req.Close = true
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	stream, err := c.native.Connect(ctx, tiana.TianaHTTP)
	if err != nil {
		cancel()
		return nil, err
	}
	fail := func() { stream.Close(); cancel() }
	// The stream context and deadline cover request, headers and body. Exactly
	// one native request is sent per stream, with no transport retry mechanism.
	if deadline, ok := ctx.Deadline(); ok {
		if err = stream.SetDeadline(deadline); err != nil {
			fail()
			return nil, ErrTransport
		}
	}
	if err = req.Write(stream); err != nil {
		fail()
		return nil, ErrTransport
	}
	reader := &budgetReader{source: stream, left: MaxMetadata}
	buffered := bufio.NewReaderSize(reader, 4096)
	reply, err := http.ReadResponse(buffered, req)
	if err != nil {
		fail()
		return nil, ErrProtocol
	}
	if reply.ContentLength > MaxBody || reply.StatusCode < 200 {
		reply.Body.Close()
		fail()
		return nil, ErrProtocol
	}
	reader.left = MaxBody + MaxMetadata // Includes buffered body and chunk framing.
	return &Response{Status: reply.StatusCode, Header: reply.Header, RequestID: stream.Metadata().RequestID, Body: &resourceBody{body: reply.Body, stream: stream, cancel: cancel, left: MaxBody}}, nil
}

type budgetReader struct {
	source io.Reader
	left   int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, ErrProtocol
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.source.Read(p)
	b.left -= int64(n)
	return n, err
}

type resourceBody struct {
	body   io.ReadCloser
	stream io.Closer
	cancel context.CancelFunc
	left   int64
}

func (b *resourceBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.body.Read(p)
	if int64(n) > b.left {
		b.Close()
		return 0, ErrProtocol
	}
	b.left -= int64(n)
	return n, err
}
func (b *resourceBody) Close() error {
	b.cancel()
	err := b.stream.Close()
	_ = b.body.Close()
	return err
}
