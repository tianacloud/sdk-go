package outbound

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/proxytest"
)

func TestHTTPSProxyRequiresTrustedCertificate(t *testing.T) {
	peer := proxytest.HTTP(t, "127.0.0.1:1", true)
	p, err := New(Config{AllProxy: peer.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = p.DialTunnel(ctx, Target{URL: parsed("https://target.example.test")})
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != TLS || len(peer.Requests()) != 0 {
		t.Fatalf("proxy TLS was not verified before CONNECT: %v", err)
	}
}
