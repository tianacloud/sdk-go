package fetch

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func readRequestID(t *testing.T, r *http.Request) string {
	t.Helper()
	var head [10]byte
	if _, err := io.ReadFull(r.Body, head[:]); err != nil {
		t.Error(err)
		return ""
	}
	raw := make([]byte, binary.BigEndian.Uint32(head[6:]))
	if _, err := io.ReadFull(r.Body, raw); err != nil {
		t.Error(err)
		return ""
	}
	var request metadata
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Error(err)
	}
	return request.RequestID
}

func TestFetchFailureRetainsGeneratedRequestID(t *testing.T) {
	for _, kind := range []string{"transport", "frame", "body"} {
		t.Run(kind, func(t *testing.T) {
			ids := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := readRequestID(t, r)
				ids <- id
				if kind == "transport" {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close()
					return
				}
				if kind == "frame" {
					_, _ = io.WriteString(w, "invalid")
					return
				}
				raw := []byte(fmt.Sprintf(`{"metadata_version":1,"request_id":%q,"status":200,"status_text":"OK","headers":[],"body_length":10}`, id))
				var head [10]byte
				copy(head[:4], "TFS1")
				binary.BigEndian.PutUint32(head[6:], uint32(len(raw)))
				w.Header().Set("Content-Type", mediaType)
				w.Header().Set("Cache-Control", "no-store")
				w.Write(head[:])
				w.Write(raw)
				w.Write([]byte("short"))
			}))
			defer server.Close()
			client := &Client{origin: server.URL, http: server.Client()}
			response, err := client.Do(t.Context(), Request{Method: "GET", PathQuery: "/"})
			if response != nil {
				defer response.Body.Close()
				_, err = io.ReadAll(response.Body)
			}
			id := <-ids
			var requestErr *Error
			want := ErrProtocol
			if kind == "transport" {
				want = ErrTransport
			}
			if !errors.As(err, &requestErr) || requestErr.RequestID != id || id == "" || !errors.Is(err, want) {
				t.Fatalf("%s error identity: %#v", kind, err)
			}
		})
	}
}

func TestFetchCancellationRetainsRequestIdentity(t *testing.T) {
	started := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- readRequestID(t, r)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := &Client{origin: server.URL, http: server.Client()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Do(ctx, Request{Method: "GET", PathQuery: "/"}); done <- err }()
	id := <-started
	cancel()
	err := <-done
	var requestErr *Error
	if !errors.As(err, &requestErr) || requestErr.RequestID != id || !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTransport) {
		t.Fatalf("cancel identity: %#v", err)
	}
}

func TestFetchQuotaFailureKeepsCodeAndLoggedRequestID(t *testing.T) {
	var requests atomic.Int32
	ids := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := readRequestID(t, r)
		if requests.Add(1) == 1 {
			ids <- id
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":{"code":"QUOTA_EXCEEDED","message":"synthetic-detail-not-for-logs"}}`)
	}))
	defer server.Close()
	client := &Client{origin: server.URL, http: server.Client()}
	_, err := client.Do(t.Context(), Request{Method: "GET", PathQuery: "/"})
	id := <-ids
	var requestErr *Error
	if !errors.As(err, &requestErr) || requestErr.Status != http.StatusForbidden || requestErr.RequestID != id || id == "" {
		t.Fatalf("quota error identity: %#v", err)
	}
	if requestErr.Code != "QUOTA_EXCEEDED" {
		t.Errorf("quota code: %q", requestErr.Code)
	}
	var output bytes.Buffer
	log.New(&output, "", 0).Print(err)
	if !strings.Contains(output.String(), "request_id="+id) || !strings.Contains(output.String(), "QUOTA_EXCEEDED") {
		t.Errorf("quota diagnostic log: %q", output.String())
	}
	if strings.Contains(output.String(), "synthetic-detail-not-for-logs") {
		t.Errorf("response detail appeared in log: %q", output.String())
	}
	if requests.Load() != 1 {
		t.Errorf("quota request was replayed: %d requests", requests.Load())
	}
}
