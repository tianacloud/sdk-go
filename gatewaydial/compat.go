// Package gatewaydial establishes an Endpoint compatibility preface before TLS.
// Endpoint authorization, TLS and application protocols remain with the caller.
package gatewaydial

import (
	"context"
	"net"

	"golang.org/x/net/proxy"
)

// Mode selects how the physical Gateway connection is established.
type Mode uint8

const (
	// Standard preserves the caller's existing direct or outbound proxy policy.
	Standard Mode = iota
	// Compat connects directly to the Endpoint and negotiates its SOCKS5 preface.
	Compat
)

func (m Mode) Valid() bool { return m == Standard || m == Compat }

// DialCompat dials the physical address once, requesting the parsed Endpoint
// hostname at logical port 443. It does not use environment proxy settings or
// resolve the logical destination. The caller owns the returned socket and must
// establish verified TLS with the same Endpoint before sending credentials.
// ctx must cover the entire connection setup, including subsequent TLS.
func DialCompat(ctx context.Context, endpoint, dialAddress string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", dialAddress, nil, &net.Dialer{})
	if err != nil {
		return nil, &Error{cause: err}
	}
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(endpoint, "443"))
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, &Error{cause: err}
	}
	return conn, nil
}

// Error reports the establishment stage without disclosing peer-supplied text.
type Error struct{ cause error }

func (*Error) Error() string   { return "compatibility transport establishment failed" }
func (e *Error) Unwrap() error { return e.cause }
