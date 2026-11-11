package gatewaydial

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tianacloud/sdk-go/internal/compattest"
)

const endpoint = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test"

func TestSetupCancellationDoesNotOwnSuccessfulConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if err = compattest.Accept(c, endpoint); err == nil {
			_, err = io.Copy(c, c)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	c, err := DialCompat(ctx, endpoint, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	<-ctx.Done()
	// Let the original setup deadline pass without replacing the socket deadline.
	time.Sleep(220 * time.Millisecond)
	guard := time.AfterFunc(2*time.Second, func() { c.Close() })
	defer guard.Stop()
	if _, err := c.Write([]byte("TLS follows")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("TLS follows"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "TLS follows" {
		t.Fatal("payload changed")
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCancellationDuringPrefaceClosesSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var greeting [3]byte
		_, err = io.ReadFull(c, greeting[:])
		close(accepted)
		if err == nil {
			_, err = c.Read(greeting[:1])
		}
		done <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := DialCompat(ctx, endpoint, l.Addr().String())
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	<-accepted
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if err := <-done; err != io.EOF {
		t.Fatalf("socket not closed: %v", err)
	}
}
