package tiana

import (
	"bytes"
	"context"
	"crypto/tls"
	"golang.org/x/net/http2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The executable is built in a separate consumer module by consumer-smoke.sh.
func TestConsumerEcho(t *testing.T) {
	binary := os.Getenv("TIANA_CONSUMER_BINARY")
	if binary == "" {
		t.Skip("run scripts/consumer-smoke.sh for the separate-module consumer")
	}
	const token = "synthetic-consumer-token"
	received := make(chan string, 1)
	server := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r.Header.Get("Proxy-Authorization")
			echoHandler(w, r)
		})})
	})
	cert, err := filepath.Abs("testdata/tls/endpoint_certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TIANA_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TIANA_ENDPOINT="+testEndpoint+testEndpointSuffix, "TIANA_GATEWAY_ADDRESS="+server.listener.Addr().String(), "TIANA_CA_FILE="+cert, "TIANA_TOKEN="+token, "TIANA_DIAL_ADDRESS=invalid-removed-address", "TIANA_GATEWAY_HOST=invalid-removed-host", "TIANA_GATEWAY_PORT=invalid-removed-port", "TIANA_TOKEN_FILE="+filepath.Join(t.TempDir(), "nonexistent-retired-token-file"))
	payload := bytes.Repeat([]byte("consumer-go\x00\xff"), 8192)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("consumer failed: %v (stderr %d bytes)", err, stderr.Len())
	}
	select {
	case got := <-received:
		if got != "Bearer "+token {
			t.Fatal("consumer did not use explicit token")
		}
	default:
		t.Fatal("consumer did not connect")
	}
	want := append([]byte("HELLO"), payload...)
	want = append(want, []byte("EOF")...)
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("consumer bytes mismatch: got %d want %d", stdout.Len(), len(want))
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected consumer stderr (%d bytes)", stderr.Len())
	}
}
