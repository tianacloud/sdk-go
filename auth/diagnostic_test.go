package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestRequestObserverPrecedesNetworkAndCannotChangeOutcome(t *testing.T) {
	var observed atomic.Value
	observed.Store("")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if observed.Load().(string) == "" || r.Header.Get("X-Request-ID") != observed.Load().(string) {
			t.Error("request reached network before its identity was observed")
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL)
	client := &Client{origin: origin, http: server.Client(), onRequestID: func(id string) {
		observed.Store(id)
		panic("diagnostic callback failure")
	}}
	var result struct{ OK bool }
	status, err := client.doJSONWithHeadersStatus(context.Background(), "GET", "/check", nil, "", nil, &result)
	if err != nil || status != 200 || !result.OK {
		t.Fatalf("callback changed request result: %d %v %+v", status, err, result)
	}
	first := observed.Load().(string)
	server.Close()
	_, err = client.doJSONWithHeadersStatus(context.Background(), "GET", "/check", nil, "", nil, &result)
	if err == nil || observed.Load().(string) == first || RequestIDOf(err) != observed.Load().(string) {
		t.Fatalf("network failure identity mismatch: %q %v", observed.Load().(string), err)
	}
}

func TestPollTerminalErrorsKeepRequestIdentity(t *testing.T) {
	for _, tc := range []struct {
		status string
		cause  error
	}{{"denied", ErrTransactionDenied}, {"expired", ErrTransactionExpired}, {"completed", ErrTransactionCompleted}} {
		t.Run(tc.status, func(t *testing.T) {
			var id string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id = r.Header.Get("X-Request-ID")
				fmt.Fprintf(w, `{"status":%q}`, tc.status)
			}))
			defer server.Close()
			origin, _ := url.Parse(server.URL)
			client := &Client{origin: origin, http: server.Client()}
			result, err := client.PollAuthTransaction(context.Background(), AuthTransaction{ID: "at-test", ClientSecret: "fixture"})
			if !errors.Is(err, tc.cause) || result.Status != tc.status || id == "" || RequestIDOf(err) != id {
				t.Fatalf("status=%s error=%v request=%s", result.Status, err, RequestIDOf(err))
			}
		})
	}
}
