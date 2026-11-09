package functionfiles

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tianacloud/sdk-go/internal/functioncontext"
	"golang.org/x/net/http/httpguts"
)

const origin = "http://supervisor.tiana.com:80"

var httpClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil, DisableCompression: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Client addresses the Function owner's files root, optionally below one Web ID.
// Construct clients with function.Files, FilesByWebApp or FilesFromRequest.
// A client can be reused concurrently; request-derived scopes belong to that request.
type Client struct{ webID string }

func New(webID string) *Client { return &Client{webID: webID} }
func NewWeb(webID string) (*Client, error) {
	if !relative(webID, false) || strings.Contains(webID, "/") {
		return nil, invalid("")
	}
	return New(webID), nil
}
func relative(path string, directory bool) bool {
	if strings.HasPrefix(path, "/") {
		return false
	}
	if directory {
		path = strings.TrimSuffix(path, "/")
		if path == "" {
			return true
		}
	}
	if path == "" || !utf8.ValidString(path) || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	lower := strings.ToLower(path)
	for _, encoded := range []string{"%2e", "%2f", "%5c", "%25"} {
		if strings.Contains(lower, encoded) {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func invalid(writeID string) *Error {
	return &Error{Code: "FILE_INVALID_ARGUMENT", Message: "invalid file argument", Stage: "validate", Outcome: "not_started", WriteID: writeID}
}
func newWriteID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}
func transportError(cause error, write, notStarted bool, writeID string) *Error {
	e := &Error{Code: "FILE_REQUEST_FAILED", Message: "file request failed", Stage: "transport", Outcome: "failed", WriteID: writeID, cause: cause}
	if notStarted {
		e.Outcome = "not_started"
	} else if write {
		e.Code = "FILE_RESULT_UNKNOWN"
		e.Outcome = "unknown"
		e.Message = "file operation result is unknown"
	}
	return e
}
func (c *Client) send(ctx context.Context, method, route string, query url.Values, body io.Reader, size int64, headers http.Header, writeID string) (*http.Response, error) {
	write := method == http.MethodPut || method == http.MethodDelete
	if err := ctx.Err(); err != nil {
		return nil, transportError(err, write, true, writeID)
	}
	if c.webID != "" {
		query.Set("web_id", c.webID)
	}
	request, err := http.NewRequestWithContext(ctx, method, origin+route+"?"+query.Encode(), body)
	if err != nil {
		return nil, invalid(writeID)
	}
	request.GetBody = nil
	if method == http.MethodPut {
		request.ContentLength = size
		if size == 0 {
			request.Body = http.NoBody
		}
	}
	request.Header = headers
	identity := functioncontext.FromContext(ctx)
	if identity.RequestID == "" {
		identity.RequestID = rand.Text()
	}
	request.Header.Set("x-request-id", identity.RequestID)
	if identity.Traceparent != "" {
		request.Header.Set("traceparent", identity.Traceparent)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		e := transportError(err, write, false, writeID)
		e.RequestID = identity.RequestID
		return nil, e
	}
	success := (method == http.MethodGet || method == http.MethodHead) && response.StatusCode == 200 || method == http.MethodGet && route == "/files/object" && response.StatusCode == 206 || method == http.MethodPut && response.StatusCode == 201 || method == http.MethodDelete && response.StatusCode == 204
	if success {
		return response, nil
	}
	defer response.Body.Close()
	var failure *Error
	if method == http.MethodHead {
		failure = &Error{Code: response.Header.Get("x-tiana-file-error"), Stage: "get", Outcome: "failed"}
		if response.StatusCode == 400 {
			failure.Stage = "validate"
		}
		if response.StatusCode == 400 || response.StatusCode == 503 {
			failure.Outcome = "not_started"
		}
		failure.Message = message(failure.Code)
	} else {
		var envelope struct {
			Error *Error `json:"error"`
		}
		if err = json.NewDecoder(response.Body).Decode(&envelope); err == nil && envelope.Error != nil && envelope.Error.Code != "" {
			failure = envelope.Error
		} else {
			failure = transportError(err, write, false, writeID)
		}
	}
	failure.StatusCode = response.StatusCode
	failure.RequestID = response.Header.Get("x-request-id")
	if failure.WriteID == "" {
		failure.WriteID = writeID
	}
	return nil, failure
}
func decode(response *http.Response, out any, writeID string, write bool) error {
	defer response.Body.Close()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	err := json.NewDecoder(response.Body).Decode(&envelope)
	if err == nil {
		if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			err = io.ErrUnexpectedEOF
		} else {
			err = json.Unmarshal(envelope.Data, out)
		}
	}
	if err != nil {
		e := transportError(err, write, false, writeID)
		e.StatusCode = response.StatusCode
		e.RequestID = response.Header.Get("x-request-id")
		return e
	}
	return nil
}
func message(code string) string {
	switch code {
	case "FILE_INVALID_ARGUMENT":
		return "invalid file argument"
	case "FILE_NOT_FOUND":
		return "file not found"
	case "FILE_NOT_CONFIGURED":
		return "file storage is not configured"
	case "FILE_UNSUPPORTED_OBJECT":
		return "unsupported file object"
	case "FILE_RANGE_NOT_SATISFIABLE":
		return "file range is not satisfiable"
	default:
		return "file request failed"
	}
}
func (c *Client) small(ctx context.Context, route, path string, query url.Values, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if route != "/files/capabilities" {
		if !relative(path, route == "/files/list") {
			return invalid("")
		}
		query.Set("path", path)
	}
	response, err := c.send(ctx, http.MethodGet, route, query, nil, 0, make(http.Header), "")
	if err != nil {
		return err
	}
	return decode(response, out, "", false)
}

// List reads a single directory page. Returned paths are relative to this client.
func (c *Client) List(ctx context.Context, path string, options ListOptions) (Page, error) {
	var result Page
	query := url.Values{}
	if options.Cursor != "" {
		query.Set("cursor", options.Cursor)
	}
	err := c.small(ctx, "/files/list", path, query, &result)
	return result, err
}
func (c *Client) Metadata(ctx context.Context, path string) (Metadata, error) {
	var result Metadata
	err := c.small(ctx, "/files/metadata", path, url.Values{}, &result)
	return result, err
}

// Get returns the original bytes and headers. The caller must close Body.
// An empty Method selects GET; HEAD ignores Range. Body read failures remain read errors.
func (c *Client) Get(ctx context.Context, path string, options GetOptions) (*http.Response, error) {
	method := options.Method
	if method == "" {
		method = http.MethodGet
	}
	if !relative(path, false) || method != http.MethodGet && method != http.MethodHead {
		return nil, invalid("")
	}
	headers := make(http.Header)
	if method == http.MethodGet && options.Range != "" {
		if !httpguts.ValidHeaderFieldValue(options.Range) {
			return nil, invalid("")
		}
		headers.Set("Range", options.Range)
	}
	return c.send(ctx, method, "/files/object", url.Values{"path": {path}}, nil, 0, headers, "")
}

// GetURL returns the public file entry URL. A browser still needs its own file grant.
func (c *Client) GetURL(ctx context.Context, path string) (string, error) {
	var result struct {
		URL string `json:"url"`
	}
	err := c.small(ctx, "/files/url", path, url.Values{}, &result)
	return result.URL, err
}

// Put streams exactly Size bytes. Overwrite deletes the old object before conditional
// creation and is not atomic. An unknown result must be checked with Metadata.
func (c *Client) Put(ctx context.Context, path string, reader io.Reader, options PutOptions) (PutReceipt, error) {
	id := options.WriteID
	if id == "" {
		id = newWriteID()
	}
	if !relative(path, false) || options.Size < 0 || !httpguts.ValidHeaderFieldValue(id) || options.Size > 0 && reader == nil {
		return PutReceipt{}, invalid(id)
	}
	contentType := options.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if _, _, err := mime.ParseMediaType(contentType); err != nil || !httpguts.ValidHeaderFieldValue(contentType) {
		return PutReceipt{}, invalid(id)
	}
	if options.Size == 0 {
		reader = http.NoBody
	}
	headers := make(http.Header)
	headers.Set("Content-Type", contentType)
	query := url.Values{"path": {path}, "overwrite": {fmt.Sprint(options.Overwrite)}, "write_id": {id}}
	response, err := c.send(ctx, http.MethodPut, "/files/object", query, reader, options.Size, headers, id)
	if err != nil {
		return PutReceipt{}, err
	}
	var result PutReceipt
	err = decode(response, &result, id, true)
	if err == nil && (result.Path != path || result.Size != options.Size || result.WriteID != id || result.ETag == "") {
		failure := transportError(fmt.Errorf("incomplete file write receipt"), true, false, id)
		failure.StatusCode = response.StatusCode
		failure.RequestID = response.Header.Get("x-request-id")
		return PutReceipt{}, failure
	}
	return result, err
}

// Delete removes the current object; a missing object also succeeds.
func (c *Client) Delete(ctx context.Context, path string) error {
	if !relative(path, false) {
		return invalid("")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := c.send(ctx, http.MethodDelete, "/files/object", url.Values{"path": {path}}, nil, 0, make(http.Header), "")
	if err != nil {
		return err
	}
	return response.Body.Close()
}
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var result Capabilities
	err := c.small(ctx, "/files/capabilities", "", url.Values{}, &result)
	return result, err
}
