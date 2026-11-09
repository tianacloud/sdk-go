package functionfiles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/functioncontext"
)

func serve(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	previous := httpClient
	httpClient = &http.Client{Transport: transport, CheckRedirect: previous.CheckRedirect}
	t.Cleanup(func() { httpClient = previous; transport.CloseIdleConnections(); server.Close() })
}
func TestFileMethodsUseSupervisorContract(t *testing.T) {
	raw, err := os.ReadFile("function-files.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Origin     string                                   `json:"origin"`
		Operations map[string]struct{ Method, Path string } `json:"operations"`
	}
	if err = json.Unmarshal(raw, &contract); err != nil || contract.Origin != origin {
		t.Fatal(err)
	}
	var called []string
	step := ""
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		expected := contract.Operations[step]
		if r.Host != "supervisor.tiana.com:80" || r.Method != expected.Method || r.URL.Path != expected.Path || r.URL.Query().Get("web_id") != "web-a" {
			t.Errorf("wrong request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("x-request-id") != "request-one" || r.Header.Get("traceparent") != "trace-one" {
			t.Error("diagnostics lost")
		}
		if step != "capabilities" && r.URL.Query().Get("path") != "images/中文 +%#?.txt" {
			t.Error(r.URL.RawQuery)
		}
		called = append(called, step)
		w.Header().Set("x-request-id", "response-one")
		switch step {
		case "list":
			if r.URL.Query().Get("cursor") != "opaque+next" {
				t.Error("cursor changed")
			}
			io.WriteString(w, `{"data":{"entries":[{"path":"images/中文 +%#?.txt","is_dir":false,"size":3}],"next_cursor":"next"},"future":"ignored"}`)
		case "metadata":
			io.WriteString(w, `{"data":{"path":"images/中文 +%#?.txt","size":3,"etag":"\"tag\"","content_type":"text/plain","write_id":"one","last_modified":"2026-11-09T00:00:00Z"}}`)
		case "get":
			if r.Header.Get("Range") != "bytes=0-1" || r.Header.Get("Accept-Encoding") != "" {
				t.Error("range/compression policy")
			}
			w.Header().Set("Content-Range", "bytes 0-1/3")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(206)
			w.Write([]byte{0x1f, 0x8b})
		case "head":
			if r.Header.Get("Range") != "" {
				t.Error("HEAD has range")
			}
			w.Header().Set("Content-Length", "3")
		case "url":
			io.WriteString(w, `{"data":{"url":"https://files.example/scope/images/a.txt"}}`)
		case "put":
			b, e := io.ReadAll(r.Body)
			if e != nil || string(b) != "abc" || r.ContentLength != 3 || r.Header.Get("Content-Type") != "text/plain" || r.URL.Query().Get("overwrite") != "true" || r.URL.Query().Get("write_id") != "one" {
				t.Error("PUT input mismatch", e)
			}
			w.WriteHeader(201)
			io.WriteString(w, `{"data":{"path":"images/中文 +%#?.txt","size":3,"etag":"\"tag\"","write_id":"one"}}`)
		case "delete":
			w.WriteHeader(204)
		case "capabilities":
			io.WriteString(w, `{"data":{"max_file_bytes":5368709120,"write_blocked":true}}`)
		}
	})
	inbound := httptest.NewRequest("GET", "/", nil)
	inbound.Header.Set("x-request-id", "request-one")
	inbound.Header.Set("traceparent", "trace-one")
	ctx := functioncontext.FromRequest(inbound)
	client, e := NewWeb("web-a")
	if e != nil {
		t.Fatal(e)
	}
	path := "images/中文 +%#?.txt"
	step = "list"
	page, e := client.List(ctx, path, ListOptions{Cursor: "opaque+next"})
	if e != nil || len(page.Entries) != 1 || page.Entries[0].Path != path || page.NextCursor != "next" {
		t.Fatal(page, e)
	}
	step = "metadata"
	meta, e := client.Metadata(ctx, path)
	if e != nil || meta.Size != 3 || meta.WriteID != "one" || meta.LastModified.IsZero() {
		t.Fatal(meta, e)
	}
	step = "get"
	response, e := client.Get(ctx, path, GetOptions{Range: "bytes=0-1"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || !bytes.Equal(b, []byte{0x1f, 0x8b}) || response.ContentLength != 2 || response.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal(response, e)
	}
	step = "head"
	response, e = client.Get(ctx, path, GetOptions{Method: "HEAD", Range: "ignored"})
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.ContentLength != 3 {
		t.Fatal(response.ContentLength)
	}
	step = "url"
	public, e := client.GetURL(ctx, path)
	if e != nil || public != "https://files.example/scope/images/a.txt" {
		t.Fatal(public, e)
	}
	step = "put"
	receipt, e := client.Put(ctx, path, strings.NewReader("abc"), PutOptions{Size: 3, ContentType: "text/plain", Overwrite: true, WriteID: "one"})
	if e != nil || receipt.Size != 3 || receipt.Path != path || receipt.WriteID != "one" {
		t.Fatal(receipt, e)
	}
	step = "delete"
	if e = client.Delete(ctx, path); e != nil {
		t.Fatal(e)
	}
	step = "capabilities"
	capabilities, e := client.Capabilities(ctx)
	if e != nil || !capabilities.WriteBlocked || capabilities.MaxFileBytes != 5368709120 {
		t.Fatal(capabilities, e)
	}
	if len(called) != len(contract.Operations) {
		t.Fatal(called)
	}
}

func TestFileErrorsAndUnknownWrites(t *testing.T) {
	for _, mode := range []string{"put-truncated-success", "put-incomplete-receipt", "put-truncated-error", "put-conflict", "head-missing", "cancelled", "redirect", "empty"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			serve(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("x-request-id", "error-request")
				switch mode {
				case "put-truncated-success":
					w.WriteHeader(201)
					io.WriteString(w, `{"data":`)
				case "put-incomplete-receipt":
					w.WriteHeader(201)
					io.WriteString(w, `{"data":{}}`)
				case "put-truncated-error":
					w.WriteHeader(409)
					io.WriteString(w, `{"error":{"delete_confirmed":true,`)
				case "put-conflict":
					w.WriteHeader(409)
					io.WriteString(w, `{"error":{"code":"FILE_EXISTS","message":"exists","stage":"put","outcome":"failed","delete_confirmed":true,"write_id":"write-one"}}`)
				case "head-missing":
					w.Header().Set("x-tiana-file-error", "FILE_NOT_FOUND")
					w.WriteHeader(404)
				case "redirect":
					w.Header().Set("Location", origin+"/files/object?path=other")
					w.WriteHeader(307)
				case "empty":
					if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.Query().Get("write_id") == "" {
						t.Error("empty PUT framing")
					}
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(map[string]any{"data": PutReceipt{Path: "a", ETag: "tag", WriteID: r.URL.Query().Get("write_id")}})
				default:
					t.Error("cancelled request was sent")
				}
			})
			c := New("")
			ctx := context.Background()
			var err error
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode == "head-missing" {
				_, err = c.Get(ctx, "a", GetOptions{Method: "HEAD"})
			} else {
				_, err = c.Put(ctx, "a", nil, PutOptions{Size: 0, WriteID: map[bool]string{true: "write-one"}[mode != "empty"]})
			}
			if mode == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var failure *Error
			if !errors.As(err, &failure) {
				t.Fatal(err)
			}
			switch mode {
			case "put-conflict":
				if failure.Code != "FILE_EXISTS" || !failure.DeleteConfirmed || failure.Outcome != "failed" {
					t.Fatal(failure)
				}
			case "head-missing":
				if failure.Stage != "get" || failure.Code != "FILE_NOT_FOUND" || failure.Outcome != "failed" {
					t.Fatal(failure)
				}
			case "cancelled":
				if failure.Outcome != "not_started" || !errors.Is(err, context.Canceled) || calls.Load() != 0 {
					t.Fatal(failure, calls.Load())
				}
			default:
				if failure.Code != "FILE_RESULT_UNKNOWN" || failure.Outcome != "unknown" || failure.DeleteConfirmed || failure.WriteID != "write-one" || calls.Load() != 1 {
					t.Fatal(failure, calls.Load())
				}
			}
		})
	}
}

func TestFilePathsAndInputValidationBeforeIO(t *testing.T) {
	var calls atomic.Int32
	serve(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	for _, path := range []string{"", "/other", "../other", "a/../other", "a//b", "a\\b", "a%2fb", "a%252fb", "a%2eb", "a\x00b"} {
		if _, err := New("").Metadata(t.Context(), path); err == nil {
			t.Fatal(path)
		}
	}
	for _, web := range []string{"", "..", "a/b", "a%2fb"} {
		if _, err := NewWeb(web); err == nil {
			t.Fatal(web)
		}
	}
	for _, option := range []PutOptions{{Size: -1}, {WriteID: "bad\r\nid", Overwrite: true}, {ContentType: "text/plain\r\nFoo: bad", Overwrite: true}} {
		if _, err := New("").Put(t.Context(), "a", nil, option); err == nil {
			t.Fatal(option)
		}
	}
	if calls.Load() != 0 {
		t.Fatal(calls.Load())
	}
}

func TestPutStreamsBeforeReaderFinishesAndGetBodyCancellation(t *testing.T) {
	first := make(chan struct{})
	release := make(chan struct{})
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			var b [1]byte
			if _, e := io.ReadFull(r.Body, b[:]); e != nil {
				t.Error(e)
				return
			}
			close(first)
			<-release
			rest, e := io.ReadAll(r.Body)
			if e != nil || string(b[:])+string(rest) != "abc" {
				t.Error(e)
			}
			w.WriteHeader(201)
			io.WriteString(w, `{"data":{"path":"a","size":3,"etag":"tag","write_id":"stream"}}`)
		} else {
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("a"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	})
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := New("").Put(t.Context(), "a", reader, PutOptions{Size: 3, WriteID: "stream"})
		done <- err
	}()
	if _, e := writer.Write([]byte("a")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("upload buffered before EOF")
	}
	close(release)
	writer.Write([]byte("bc"))
	writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	response, err := New("").Get(ctx, "a", GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFileClientTransportPolicy(t *testing.T) {
	transport := httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || httpClient.Timeout != 0 {
		t.Fatal("stream policy")
	}
	if !reflect.DeepEqual(New("web-a"), New("web-a")) {
		t.Fatal("constructor state")
	}
}
