package tiana

import (
	"bytes"
	"context"
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
	server := echoServer(t)
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
	cmd.Env = append(cmd.Env, "TIANA_ENDPOINT="+testEndpoint+testEndpointSuffix, "TIANA_DIAL_ADDRESS="+server.listener.Addr().String(), "TIANA_CA_FILE="+cert)
	payload := bytes.Repeat([]byte("consumer-go\x00\xff"), 8192)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("consumer failed: %v (stderr %d bytes)", err, stderr.Len())
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
