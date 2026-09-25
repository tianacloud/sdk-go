//go:build integration

package tiana_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tiana "github.com/tianacloud/sdk-go"
)

func TestGatewaySnapshot(t *testing.T) {
	root := os.Getenv("TIANA_GATEWAY_FIXTURE")
	if root == "" {
		t.Fatal("TIANA_GATEWAY_FIXTURE must identify the isolated fixed Gateway fixture")
	}
	data, err := os.ReadFile(filepath.Join(root, "ready.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ready map[string]string
	if err := json.Unmarshal(data, &ready); err != nil {
		t.Fatal(err)
	}
	if ready["gateway_commit"] != "9f5aa69b24aa6e04112baaf8d1e17c0639fd293b" {
		t.Fatal("unexpected Gateway source")
	}
	ca, err := os.ReadFile(filepath.Join(root, "fixtures/gateway.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	tokenData, err := os.ReadFile(filepath.Join(root, "fixtures/synthetic-token.txt"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := tiana.NewToken(strings.TrimSpace(string(tokenData)))
	clear(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := tiana.NewToken("tia_0" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	cases := []struct {
		name, address string
		token         *tiana.Token
		status        int
		code, mode    string
		profile       tiana.Profile
	}{
		{"anonymous", ready["anonymous_address"], nil, 200, "", "DISABLED", tiana.HranaHTTP},
		{"authenticated", ready["token_address"], token, 200, "", "TOKEN_REQUIRED", tiana.HranaHTTP},
		{"missing_token", ready["token_address"], nil, 407, "AUTH_REQUIRED", "", tiana.HranaHTTP},
		{"wrong_token", ready["token_address"], wrong, 407, "ACCESS_DENIED", "", tiana.HranaHTTP},
		{"unavailable", ready["POLICY_UNAVAILABLE"], nil, 503, "POLICY_UNAVAILABLE", "", tiana.HranaHTTP},
	}

	for _, profile := range []tiana.Profile{tiana.HranaWebSocket, tiana.MySQL, tiana.PostgreSQL, tiana.Git} {
		for _, base := range cases[:2] {
			base.name += "/" + string(profile)
			base.profile = profile
			cases = append(cases, base)
		}
	}
	for _, item := range []struct {
		name, code string
		status     int
	}{
		{"AUTHORIZATION_EXPIRED", "AUTHORIZATION_EXPIRED", 407}, {"CALLER_DEADLINE", "CALLER_DEADLINE", 504},
		{"ENDPOINT_MISMATCH", "ENDPOINT_MISMATCH", 421}, {"CONNECTION_LIMIT", "CONNECTION_LIMIT", 429},
		{"INSTANCE_UNAVAILABLE", "INSTANCE_UNAVAILABLE", 503}, {"ACTIVATION_TIMEOUT", "ACTIVATION_TIMEOUT", 504},
		{"MALFORMED_CONNECT", "MALFORMED_CONNECT", 400},
		{"quota_compute", "QUOTA_EXCEEDED", 403}, {"quota_storage", "QUOTA_EXCEEDED", 403}, {"quota_both", "QUOTA_EXCEEDED", 403},
	} {
		tc := cases[0]
		tc.name, tc.address, tc.code, tc.status, tc.mode = item.name, ready[item.name], item.code, item.status, ""
		cases = append(cases, tc)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.address == "" {
				t.Fatal("missing fixture address")
			}
			c, err := tiana.NewClient(tiana.Config{Endpoint: ready["endpoint"], DialAddress: tc.address, Token: tc.token, RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream, err := c.Connect(ctx, tc.profile)
			if tc.status != 200 {
				var e *tiana.Error
				if !errors.As(err, &e) || e.Status != tc.status || e.Code != tc.code || e.Committed || e.Retryable() != (tc.status == 503 || tc.status == 429 || tc.code == "ACTIVATION_TIMEOUT") {
					t.Fatalf("wrong refusal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if stream.Metadata().AuthMode != tc.mode {
				t.Fatal("auth mode mismatch")
			}
			greeting := make([]byte, len(ready["greeting"]))
			if _, err := io.ReadFull(stream, greeting); err != nil {
				t.Fatal(err)
			}
			if string(greeting) != ready["greeting"] {
				t.Fatal("greeting mismatch")
			}
			payload := bytes.Repeat([]byte("go-native\x00\xff"), 32768)
			done := make(chan error, 1)
			go func() {
				_, err := stream.Write(payload)
				if err == nil {
					err = stream.CloseWrite()
				}
				done <- err
			}()
			got, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, append(payload, []byte(ready["eof_tail"])...)) {
				t.Fatalf("echo/half-close mismatch: %d bytes", len(got))
			}
			t.Logf("fixed Gateway: %s, %d payload bytes, greeting and post-END_STREAM tail verified", tc.mode, len(payload))
		})
	}
	t.Run("cancel_isolation", func(t *testing.T) {
		c, err := tiana.NewClient(tiana.Config{Endpoint: ready["endpoint"], DialAddress: ready["anonymous_address"], RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		first, err := c.Connect(ctx, tiana.HranaHTTP)
		if err != nil {
			t.Fatal(err)
		}
		siblingCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		second, err := c.Connect(siblingCtx, tiana.HranaHTTP)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		for _, stream := range []*tiana.Tunnel{first, second} {
			if _, err := io.ReadFull(stream, make([]byte, len(ready["greeting"]))); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		if _, err := first.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error: %v", err)
		}
		if _, err := second.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		if err := second.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(second)
		if err != nil || string(got) != "alive"+ready["eof_tail"] {
			t.Fatal("sibling affected", err)
		}
	})
}
