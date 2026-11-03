package function

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func secretServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	old := jobClient
	jobClient = &http.Client{Transport: transport}
	t.Cleanup(func() { jobClient = old; transport.CloseIdleConnections() })
}

func TestSecretRequestContextAndErrors(t *testing.T) {
	const trace = "00-11111111111111111111111111111111-2222222222222222-01"
	secretServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-request-id") != "inbound-r" || r.Header.Get("traceparent") != trace {
			t.Errorf("request identity: %v", r.Header)
		}
		w.Header().Set("x-request-id", r.Header.Get("x-request-id"))
		w.WriteHeader(http.StatusNotFound)
	})
	inbound := httptest.NewRequest("GET", "/", nil)
	inbound.Header.Set("x-request-id", "inbound-r")
	inbound.Header.Set("traceparent", trace)
	ctx := ContextFromRequest(inbound)
	inbound.Header.Set("x-request-id", "changed-after-capture")
	_, err := (Config{"KEY": {Kind: "secret"}}).GetContext(ctx, "KEY")
	var requestErr *RequestError
	if !errors.As(err, &requestErr) || requestErr.RequestID != "inbound-r" || requestErr.Status != 404 || !errors.Is(err, ErrNotExist) {
		t.Fatalf("error identity and semantics: %#v", err)
	}
}

func TestIndependentSecretCallsAndConcurrentContextIsolation(t *testing.T) {
	ids := make(chan string, 10)
	secretServer(t, func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("x-request-id")
		ids <- id
		w.Header().Set("x-request-id", id)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := Config{"KEY": {Kind: "secret"}}
	for range 2 {
		_, err := c.Get("KEY")
		var requestErr *RequestError
		if !errors.As(err, &requestErr) || requestErr.RequestID == "" || requestErr.RequestID != <-ids {
			t.Fatalf("independent identity: %#v", err)
		}
	}
	var wg sync.WaitGroup
	for n := range 8 {
		wg.Go(func() {
			inbound := httptest.NewRequest("GET", "/", nil)
			id := fmt.Sprintf("concurrent-%d", n)
			inbound.Header.Set("x-request-id", id)
			_, err := c.GetContext(ContextFromRequest(inbound), "KEY")
			var requestErr *RequestError
			if !errors.As(err, &requestErr) || requestErr.RequestID != id {
				t.Errorf("concurrent identity: %#v", err)
			}
		})
	}
	wg.Wait()
}

func TestSecretCancellationKeepsGeneratedIdentity(t *testing.T) {
	started := make(chan string, 1)
	secretServer(t, func(w http.ResponseWriter, r *http.Request) {
		started <- r.Header.Get("x-request-id")
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := (Config{"KEY": {Kind: "secret"}}).GetContext(ctx, "KEY"); done <- err }()
	id := <-started
	cancel()
	err := <-done
	var requestErr *RequestError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &requestErr) || id == "" || requestErr.RequestID != id {
		t.Fatalf("cancel identity: %#v", err)
	}
}
