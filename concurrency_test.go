package tiana

import (
	"context"
	"crypto/tls"
	"errors"
	"golang.org/x/net/http2"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"testing/synctest"
	"time"
)

func TestFullWriteQueueDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newSession(a, Config{MaxStreams: 256, ConnectTimeout: time.Second})
	defer s.shutdown(failure(Closed, "test cleanup", false))
	stream, err := s.open(HranaHTTP, "req-review-queue")
	if err != nil {
		t.Fatal(err)
	}
	stream.committed = true
	for i := 0; i < cap(s.writes); i++ {
		s.writes <- frameWrite{}
	}
	stream.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("x")); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("wrong deadline error: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Write still blocked on full queue 180ms after deadline")
		s.shutdown(failure(Closed, "test cleanup", false))
		<-done
	}
}

func TestConcurrentConnect(t *testing.T) {
	server := echoServer(t)
	c := clientFor(t, server, func(cfg *Config) { cfg.MaxStreams = 256 })
	warm := connectFor(t, c, context.Background())
	readExact(t, warm, "HELLO")
	const count = 64
	start := make(chan struct{})
	done := make(chan error, count)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < count; i++ {
		go func() {
			<-start
			stream, err := c.Connect(ctx, HranaHTTP)
			if err == nil {
				stream.Close()
			}
			done <- err
		}()
	}
	close(start)
	failures := 0
	var first error
	for i := 0; i < count; i++ {
		if err := <-done; err != nil {
			failures++
			if first == nil {
				first = err
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d/%d concurrent Connect calls failed: %v", failures, count, first)
	}
}

func TestConcurrentConnectWireOrder(t *testing.T) {
	ids := make(chan uint32, 65)
	server := listenTest(t, testTLS(t, "endpoint"), func(conn *tls.Conn) {
		peer := newPeer(t, conn, 65535)
		if peer == nil {
			return
		}
		for {
			frame, err := peer.fr.ReadFrame()
			if err != nil {
				return
			}
			if f, ok := frame.(*http2.MetaHeadersFrame); ok {
				ids <- f.StreamID
				peer.success(f.StreamID, values(f)["tiana-request-id"], false)
			}
		}
	})
	c := clientFor(t, server, func(cfg *Config) { cfg.MaxStreams = 256 })
	warm := connectFor(t, c, context.Background())
	defer warm.Close()
	start := make(chan struct{})
	done := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func() {
			<-start
			stream, err := c.Connect(context.Background(), HranaHTTP)
			if err == nil {
				stream.Close()
			}
			done <- err
		}()
	}
	close(start)
	for i := 0; i < 64; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	previous := uint32(0)
	for i := 0; i < 65; i++ {
		current := <-ids
		if current < previous {
			t.Fatalf("new stream HEADERS out of order on wire: %d then %d", previous, current)
		}
		previous = current
	}
}

// Setting a deadline after the queue wait starts must wake it, restore credit,
// and leave an unsubmitted write safe to retry explicitly.
func TestFullWriteQueueDeadlineUpdateRestoresCredit(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newSession(a, Config{MaxStreams: 2, ConnectTimeout: time.Second})
	defer s.shutdown(failure(Closed, "test cleanup", false))
	stream, err := s.open(HranaHTTP, "req-queue-update")
	if err != nil {
		t.Fatal(err)
	}
	stream.committed = true
	for i := 0; i < cap(s.writes); i++ {
		s.writes <- frameWrite{}
	}
	result := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("abc")); result <- err }()
	stream.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline error: %v", err)
		}
	case <-time.After(time.Second):
		s.shutdown(failure(Closed, "test cleanup", false))
		<-result
		t.Fatal("deadline update did not unblock Write")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendWindow != 65535 || stream.sendWindow != 65535 {
		t.Fatalf("lost flow credit: conn=%d stream=%d", s.sendWindow, stream.sendWindow)
	}
	if stream.err != nil {
		t.Fatalf("unsubmitted write terminated stream: %v", stream.err)
	}
}

func TestQueuedWriteDeadlinePreservesSibling(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newSession(a, Config{MaxStreams: 2, ConnectTimeout: time.Second})
	defer s.shutdown(failure(Closed, "test cleanup", false))
	stream, err := s.open(HranaHTTP, "req-queued-deadline")
	if err != nil {
		t.Fatal(err)
	}
	stream.committed = true
	stream.headersStarted = true
	sibling, err := s.open(HranaHTTP, "req-sibling-deadline")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(s.writes)-1; i++ {
		s.writes <- frameWrite{}
	}
	stream.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	result := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("abc")); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline error: %v", err)
		}
	case <-time.After(time.Second):
		s.shutdown(failure(Closed, "test cleanup", false))
		<-result
		t.Fatal("reset blocked behind the full DATA queue")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stream.err == nil || !stream.finished {
		t.Fatal("queued timeout must terminate uncertain stream")
	}
	if sibling.err != nil || s.err != nil {
		t.Fatal("timeout affected sibling")
	}
}

func TestCanceledUnopenedStreamSendsNoReset(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newSession(a, Config{MaxStreams: 2, ConnectTimeout: time.Second})
	stream, err := s.open(HranaHTTP, "req-never-opened")
	if err != nil {
		t.Fatal(err)
	}
	s.abort(stream, contextFailure(context.Canceled, false))
	s.start()
	defer func() { s.shutdown(failure(Closed, "test cleanup", false)); <-s.stopped }()
	b.SetReadDeadline(time.Now().Add(time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(b, preface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(nil, b)
	if _, err := fr.ReadFrame(); err != nil {
		t.Fatal(err)
	} // client SETTINGS
	b.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if frame, err := fr.ReadFrame(); err == nil {
		t.Fatalf("canceled idle stream emitted frame %T", frame)
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
}

// Force the old timer to fire while the state mutex is held, then change the
// deadline before timeout handling can inspect that state.
func TestQueuedDeadlineChangeInvalidatesOldTimer(t *testing.T) {
	for _, clearDeadline := range []bool{false, true} {
		name := "extend"
		if clearDeadline {
			name = "clear"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				s := newSession(a, Config{MaxStreams: 1, ConnectTimeout: time.Second})
				defer s.shutdown(failure(Closed, "test cleanup", false))
				stream, err := s.open(HranaHTTP, "req-stale-timer")
				if err != nil {
					t.Fatal(err)
				}
				stream.committed = true
				stream.headersStarted = true
				stream.SetWriteDeadline(time.Now().Add(time.Second))
				result := make(chan error, 1)
				go func() { _, err := stream.Write([]byte("abc")); result <- err }()
				synctest.Wait() // send is waiting on its queued frame and deadline timer
				s.mu.Lock()
				time.Sleep(time.Second)
				// Let the expired-timer handler reach the mutex before changing it.
				for i := 0; i < 10; i++ {
					runtime.Gosched()
				}
				stream.writeDeadline = time.Now().Add(time.Hour)
				if clearDeadline {
					stream.writeDeadline = time.Time{}
				}
				s.signalLocked()
				s.mu.Unlock()
				request := <-s.writes
				if request.cleanup != nil {
					request.cleanup()
				}
				request.result <- nil
				if err := <-result; err != nil {
					t.Fatalf("stale timer failed extended/cleared Write: %v", err)
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				if stream.err != nil {
					t.Fatal("stale timer terminated stream")
				}
			})
		})
	}
}
