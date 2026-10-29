package outbound

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/proxytest"
)

func TestSOCKSAuthenticationFailureIsNotRetriedOrExposed(t *testing.T) {
	peer := proxytest.SOCKS(t, "127.0.0.1:1", true)
	u, _ := url.Parse(peer.URL)
	u.User = url.UserPassword("user", "secret-canary")
	p, err := New(Config{AllProxy: u.String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = p.DialTunnel(ctx, Target{URL: parsed("https://target.example.test")})
	var failure *Error
	if !errors.As(err, &failure) || len(peer.Requests()) != 1 || strings.Contains(err.Error(), "secret-canary") || strings.Contains(err.Error(), "target.example.test") {
		t.Fatalf("unsafe SOCKS refusal: %v", err)
	}
}
