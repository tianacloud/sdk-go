// echo copies stdin through a CONNECT tunnel and writes received bytes to
// stdout. Use it with a byte-echo upstream, including the local test fixture.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	tiana "github.com/tianacloud/sdk-go"
)

func run() error {
	cfg := tiana.Config{Endpoint: os.Getenv("TIANA_ENDPOINT"), DialAddress: os.Getenv("TIANA_DIAL_ADDRESS")}
	if path := os.Getenv("TIANA_CA_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read CA file failed")
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(data) {
			return fmt.Errorf("invalid CA file")
		}
	}
	if path := os.Getenv("TIANA_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read token file failed")
		}
		cfg.Token, err = tiana.NewToken(strings.TrimSpace(string(data)))
		clear(data)
		if err != nil {
			return err
		}
	}
	c, err := tiana.NewClient(cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	stream, err := c.Connect(ctx, tiana.HranaHTTP)
	if err != nil {
		return err
	}
	defer stream.Close()
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(stream, os.Stdin)
		if err == nil {
			err = stream.CloseWrite()
		}
		if err != nil {
			stream.Close()
		}
		written <- err
	}()
	_, err = io.Copy(os.Stdout, stream)
	if err != nil {
		return err
	}
	return <-written
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
