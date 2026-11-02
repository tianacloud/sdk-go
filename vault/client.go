// Package vault implements the user secrets store's four HTTP operations.
package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tianacloud/sdk-go/fetch"
)

var ErrNotExist = errors.New("vault: secret does not exist")
var ErrResultUnknown = errors.New("vault: request outcome may be unknown")

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("vault: HTTP %d (%s)", e.Status, e.Code) }

type Entry struct {
	Key     string `json:"key"`
	Version uint64 `json:"version"`
}
type Secret struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Version uint64 `json:"version"`
}
type SetResult struct {
	Key     string `json:"key"`
	Version uint64 `json:"version"`
	Changed bool   `json:"changed"`
}
type Page struct {
	Items      []Entry `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// Client holds the existing Gateway Fetch transport and optional Get credential.
// Construct the Fetch client with DialAddress for platform internal callers.
type Client struct {
	transport  *fetch.Client
	instance   string
	passphrase []byte
}

func (*Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "vault.Client([REDACTED])") }

func NewClient(transport *fetch.Client, instance, passphrase string) (*Client, error) {
	if transport == nil || instance == "" {
		return nil, errors.New("vault: transport and instance are required")
	}
	var key []byte
	if passphrase != "" {
		var err error
		key, err = base64.StdEncoding.DecodeString(passphrase)
		if err != nil || len(key) != 32 {
			return nil, errors.New("vault: invalid safety passphrase")
		}
	}
	return &Client{transport: transport, instance: instance, passphrase: key}, nil
}
func signature(passphrase []byte, instance, key string, timestamp int64) string {
	mac := hmac.New(sha256.New, passphrase)
	for _, part := range []string{instance, "GET", key} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		mac.Write(size[:])
		mac.Write([]byte(part))
	}
	var timeBytes [8]byte
	binary.BigEndian.PutUint64(timeBytes[:], uint64(timestamp))
	mac.Write(timeBytes[:])
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func (c *Client) Get(ctx context.Context, key string) (Secret, error) {
	if len(c.passphrase) != 32 {
		return Secret{}, errors.New("vault: Get requires a safety passphrase")
	}
	timestamp := time.Now().Unix()
	headers := []fetch.Header{{Name: "x-tiana-vault-time", Value: strconv.FormatInt(timestamp, 10)}, {Name: "x-tiana-vault-signature", Value: signature(c.passphrase, c.instance, key, timestamp)}}
	var result Secret
	err := c.call(ctx, "GET", "/secrets/"+url.PathEscape(key), nil, headers, &result)
	return result, err
}
func (c *Client) Set(ctx context.Context, key, value string) (SetResult, error) {
	body, _ := json.Marshal(struct {
		Value string `json:"value"`
	}{value})
	var result SetResult
	err := c.call(ctx, "PUT", "/secrets/"+url.PathEscape(key), body, nil, &result)
	return result, err
}
func (c *Client) Remove(ctx context.Context, key string) error {
	return c.call(ctx, "DELETE", "/secrets/"+url.PathEscape(key), nil, nil, nil)
}
func (c *Client) List(ctx context.Context, keyword, after string, pageSize int) (Page, error) {
	query := url.Values{}
	if keyword != "" {
		query.Set("keyword", keyword)
	}
	if after != "" {
		query.Set("after", after)
	}
	if pageSize > 0 {
		query.Set("page_size", strconv.Itoa(pageSize))
	}
	var result Page
	err := c.call(ctx, "GET", "/secrets?"+query.Encode(), nil, nil, &result)
	return result, err
}
func (c *Client) call(ctx context.Context, method, path string, body []byte, headers []fetch.Header, result any) error {
	response, err := c.transport.Do(ctx, fetch.Request{Method: method, PathQuery: path, Headers: headers, Body: bytes.NewReader(body), BodyLength: int64(len(body))})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.Status == http.StatusNotFound {
		return ErrNotExist
	}
	if response.Status == http.StatusGatewayTimeout {
		return ErrResultUnknown
	}
	if response.Status < 200 || response.Status >= 300 {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&failure)
		return &Error{Status: response.Status, Code: failure.Error.Code}
	}
	if result == nil {
		_, err = io.Copy(io.Discard, response.Body)
		return err
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, fetch.MaxBody)).Decode(result); err != nil {
		return ErrResultUnknown
	}
	return nil
}
