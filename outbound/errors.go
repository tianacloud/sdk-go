package outbound

import (
	"context"
	"fmt"
)

type Kind string

const (
	Configuration Kind = "configuration"
	Connect       Kind = "proxy_connect"
	TLS           Kind = "proxy_tls"
	Auth          Kind = "proxy_auth"
	Protocol      Kind = "proxy_protocol"
	Canceled      Kind = "canceled"
)

// Error deliberately does not retain peer errors, URLs, status text or secrets.
// Unwrap exposes context cancellation/deadline sentinels only.
type Error struct {
	Kind        Kind
	ProxyStatus int
	Field       string
	cause       error
}

func (e *Error) Error() string {
	message := "proxy connection failed"
	switch e.Kind {
	case Configuration:
		message = "invalid proxy configuration"
	case TLS:
		message = "proxy TLS verification or handshake failed"
	case Auth:
		message = "proxy authentication rejected"
	case Protocol:
		message = "invalid proxy handshake response"
	case Canceled:
		message = "proxy connection canceled or timed out"
	}
	switch e.Field {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		message += " (" + e.Field + ")"
	}
	if e.ProxyStatus >= 100 && e.ProxyStatus <= 599 {
		message += fmt.Sprintf(" (HTTP %d)", e.ProxyStatus)
	}
	return message
}

func (e *Error) Unwrap() error { return e.cause }
func (e *Error) Timeout() bool { return e.cause == context.DeadlineExceeded }

func configError(field string) error { return &Error{Kind: Configuration, Field: field} }
