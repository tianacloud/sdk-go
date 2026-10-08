package tiana

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Tunnel implements net.Conn. Read and Write may run concurrently. Write
// blocks on HTTP/2 flow control; no database bytes are retained for replay.
// CloseWrite sends END_STREAM while preserving the readable direction.
type Tunnel struct {
	s                                           *session
	id                                          uint32
	meta                                        Metadata
	readMu, writeMu                             sync.Mutex
	ready, done, failed                         chan struct{}
	readyOnce                                   sync.Once
	buffer                                      bytes.Buffer
	sendWindow, recvWindow                      int64
	committed, remoteEOF, writeClosed, finished bool
	headersStarted                              bool
	err                                         error
	readDeadline, writeDeadline                 time.Time
}

var _ net.Conn = (*Tunnel)(nil)

func (*Tunnel) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "tiana.Tunnel([REDACTED])") }

func (t *Tunnel) Metadata() Metadata { t.s.mu.Lock(); defer t.s.mu.Unlock(); return t.meta }

func (t *Tunnel) failLocked(err error) {
	if t.err != nil {
		return
	}
	var typed *Error
	if errors.As(err, &typed) {
		copy := *typed
		copy.Committed = t.committed
		copy.RequestID = t.meta.RequestID
		if copy.Committed {
			copy.Unprocessed = false
		}
		err = &copy
	}
	t.err = err
	clear(t.buffer.Bytes())
	t.buffer.Reset()
	wasFinished := t.finished
	t.finished = true
	close(t.failed)
	if !wasFinished {
		close(t.done)
	}
	t.readyOnce.Do(func() { close(t.ready) })
}

func (t *Tunnel) finishLocked() {
	if t.remoteEOF && t.writeClosed && !t.finished {
		t.finished = true
		delete(t.s.streams, t.id)
		close(t.done)
	}
}

func (t *Tunnel) watch(ctx context.Context, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.s.abort(t, contextFailure(ctx.Err(), false))
		return
	case <-timer.C:
		t.s.abort(t, failure(Timeout, "CONNECT response timed out", false))
		return
	case <-t.done:
		return
	case <-t.ready:
	}
	select {
	case <-ctx.Done():
		t.s.abort(t, contextFailure(ctx.Err(), true))
	case <-t.done:
	}
}

func waitChanged(ch <-chan struct{}, deadline time.Time) bool {
	if deadline.IsZero() {
		<-ch
		return true
	}
	duration := time.Until(deadline)
	if duration <= 0 {
		return false
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

func (t *Tunnel) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	s := t.s
	for {
		s.mu.Lock()
		if t.err != nil {
			err := t.err
			s.mu.Unlock()
			return 0, err
		}
		if !t.readDeadline.IsZero() && !time.Now().Before(t.readDeadline) {
			s.mu.Unlock()
			return 0, deadlineFailure(true)
		}
		if t.buffer.Len() > 0 {
			n, _ := t.buffer.Read(p)
			t.recvWindow += int64(n)
			update := !t.remoteEOF
			s.mu.Unlock()
			if update {
				s.control(func(f *http2.Framer) error { return f.WriteWindowUpdate(t.id, uint32(n)) })
			}
			return n, nil
		}
		if t.remoteEOF {
			s.mu.Unlock()
			return 0, io.EOF
		}
		changed, deadline := s.changed, t.readDeadline
		s.mu.Unlock()
		if !waitChanged(changed, deadline) {
			return 0, deadlineFailure(true)
		}
	}
}

// Write returns the bytes accepted by the physical writer. A partial failure
// after CONNECT has an unknown application outcome, regardless of byte count.
func (t *Tunnel) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	s := t.s
	written := 0
	for {
		s.mu.Lock()
		if t.err != nil {
			err := t.err
			s.mu.Unlock()
			return written, err
		}
		if t.writeClosed {
			s.mu.Unlock()
			return written, failure(Closed, "write side closed", true)
		}
		if !t.writeDeadline.IsZero() && !time.Now().Before(t.writeDeadline) {
			s.mu.Unlock()
			return written, deadlineFailure(true)
		}
		if written == len(p) {
			s.mu.Unlock()
			return written, nil
		}
		available := min(t.sendWindow, s.sendWindow, int64(frameSize), int64(len(p)-written))
		if available <= 0 {
			changed, deadline := s.changed, t.writeDeadline
			s.mu.Unlock()
			if !waitChanged(changed, deadline) {
				return written, deadlineFailure(true)
			}
			continue
		}
		t.sendWindow -= available
		s.sendWindow -= available
		s.mu.Unlock()
		data := append([]byte(nil), p[written:written+int(available)]...)
		err := t.send(frameWrite{t: t, reserved: available, cleanup: func() { clear(data) }, write: func(f *http2.Framer) error { return f.WriteData(t.id, false, data) }}, true)
		if err != nil {
			return written, err
		}
		written += int(available)
	}
}

// Header writes use Connect's context and response timeout.
func (t *Tunnel) send(request frameWrite, useWriteDeadline bool) error {
	request.result = make(chan error, 1)

	// Until enqueue succeeds the caller owns the payload and both reservations.
	for {
		t.s.mu.Lock()
		err := t.err
		if err == nil {
			err = t.s.err
		}
		var deadline time.Time
		if useWriteDeadline {
			deadline = t.writeDeadline
		}
		if err == nil && !deadline.IsZero() && !time.Now().Before(deadline) {
			err = deadlineFailure(t.committed)
		}
		if err != nil {
			t.s.sendWindow += request.reserved
			t.sendWindow += request.reserved
			t.s.signalLocked()
			t.s.mu.Unlock()
			if request.cleanup != nil {
				request.cleanup()
			}
			return err
		}
		select {
		case t.s.writes <- request:
			t.s.mu.Unlock()
			goto queued
		default:
		}
		changed := t.s.changed
		t.s.mu.Unlock()
		// Recheck the current deadline after wakeup; SetWriteDeadline may extend it.
		waitChanged(changed, deadline)
	}
queued:

	for {
		t.s.mu.Lock()
		err := t.err
		changed := t.s.changed
		var deadline time.Time
		if useWriteDeadline {
			deadline = t.writeDeadline
		}
		t.s.mu.Unlock()
		if err != nil {
			return err
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case err := <-request.result:
			if timer != nil {
				timer.Stop()
			}
			if err != nil {
				t.s.abort(t, err)
				t.s.mu.Lock()
				defer t.s.mu.Unlock()
				return t.err
			}
			return nil
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-expired:
			if err := t.expireWriteDeadline(); err != nil {
				return err
			}
		}
	}
}

// A timer may race a deadline extension or clearing. Only terminate when the
// currently installed deadline is expired, under the same lock as setters.
func (t *Tunnel) expireWriteDeadline() error {
	s := t.s
	s.mu.Lock()
	if t.err != nil {
		err := t.err
		s.mu.Unlock()
		return err
	}
	if t.writeDeadline.IsZero() || time.Now().Before(t.writeDeadline) {
		s.mu.Unlock()
		return nil
	}
	idleDraining := s.abortLocked(t, deadlineFailure(t.committed))
	err := t.err
	s.mu.Unlock()
	if idleDraining {
		s.shutdown(failure(Closed, "drained connection", false))
	}
	return err
}

func (t *Tunnel) CloseWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.s.mu.Lock()
	if t.err != nil {
		err := t.err
		t.s.mu.Unlock()
		return err
	}
	if t.writeClosed {
		t.s.mu.Unlock()
		return nil
	}
	t.s.mu.Unlock()
	if err := t.send(frameWrite{t: t, write: func(f *http2.Framer) error { return f.WriteData(t.id, true, nil) }}, true); err != nil {
		return err
	}
	t.s.mu.Lock()
	t.writeClosed = true
	t.finishLocked()
	t.s.signalLocked()
	idle := t.s.draining && len(t.s.streams) == 0
	t.s.mu.Unlock()
	if idle {
		t.s.shutdown(failure(Closed, "drained connection", false))
	}
	return nil
}

// Close cancels this stream without interrupting other tunnels on its Client.
func (t *Tunnel) Close() error         { t.s.abort(t, failure(Closed, "tunnel closed", true)); return nil }
func (t *Tunnel) LocalAddr() net.Addr  { return t.s.conn.LocalAddr() }
func (t *Tunnel) RemoteAddr() net.Addr { return t.s.conn.RemoteAddr() }
func (t *Tunnel) SetDeadline(deadline time.Time) error {
	t.s.mu.Lock()
	t.readDeadline = deadline
	t.writeDeadline = deadline
	t.s.signalLocked()
	t.s.mu.Unlock()
	return nil
}
func (t *Tunnel) SetReadDeadline(deadline time.Time) error {
	t.s.mu.Lock()
	t.readDeadline = deadline
	t.s.signalLocked()
	t.s.mu.Unlock()
	return nil
}
func (t *Tunnel) SetWriteDeadline(deadline time.Time) error {
	t.s.mu.Lock()
	t.writeDeadline = deadline
	t.s.signalLocked()
	t.s.mu.Unlock()
	return nil
}
