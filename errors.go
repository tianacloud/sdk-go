package tiana

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

type ErrorKind string

const (
	Configuration ErrorKind = "configuration"
	TCP           ErrorKind = "tcp"
	TLS           ErrorKind = "tls"
	HTTP2         ErrorKind = "http2"
	Response      ErrorKind = "response"
	Gateway       ErrorKind = "gateway"
	Timeout       ErrorKind = "timeout"
	Canceled      ErrorKind = "canceled"
	Closed        ErrorKind = "closed"
	Limit         ErrorKind = "limit"
)

// Error exposes bounded metadata, never peer diagnostics or credential bytes.
// Committed means a complete 200 response was seen; a failed committed session
// has an unknown inner outcome. No SDK operation automatically retries.
type Error struct {
	Kind        ErrorKind
	Committed   bool
	Status      int
	Code        string
	RetryAfter  time.Duration
	Unprocessed bool
	RequestID   string
	message     string
	cause       error
}

func (e *Error) Error() string {
	text := "tiana: " + string(e.Kind) + ": " + e.message
	if e.Status != 0 {
		text += fmt.Sprintf(" (HTTP %d", e.Status)
		if e.Code != "" {
			text += " " + e.Code
		}
		text += ")"
	}
	if e.Committed {
		text += "; session outcome unknown"
	}
	return text
}

func (e *Error) Unwrap() error   { return e.cause }
func (e *Error) Timeout() bool   { return e.Kind == Timeout }
func (e *Error) Temporary() bool { return e.Retryable() }
func (e *Error) Retryable() bool {
	if e.Committed {
		return false
	}
	if e.RetryAfter < time.Millisecond || e.RetryAfter > 60*time.Second {
		return false
	}
	return (e.Status == 429 && e.Code == "CONNECTION_LIMIT") ||
		(e.Status == 503 && (e.Code == "POLICY_UNAVAILABLE" || e.Code == "INSTANCE_UNAVAILABLE" || e.Code == "ACTIVATION_RESOURCE_PRESSURE" || e.Code == "ACTIVATION_NO_IDLE_POD" || e.Code == "ACTIVATION_CAPACITY_UNAVAILABLE")) ||
		(e.Status == 504 && e.Code == "ACTIVATION_TIMEOUT")
}

func failure(kind ErrorKind, message string, committed bool) *Error {
	e := &Error{Kind: kind, message: message, Committed: committed}
	if kind == Closed {
		e.cause = net.ErrClosed
	}
	return e
}

func contextFailure(err error, committed bool) *Error {
	kind := Canceled
	if err == context.DeadlineExceeded {
		kind = Timeout
	}
	e := failure(kind, "context ended", committed)
	e.cause = err
	return e
}

func deadlineFailure(committed bool) *Error {
	e := failure(Timeout, "I/O deadline exceeded", committed)
	e.cause = os.ErrDeadlineExceeded
	return e
}
