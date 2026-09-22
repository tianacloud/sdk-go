// Package tiana opens native TLS/HTTP2 CONNECT tunnels to Tiana Endpoints.
package tiana

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const Version = "0.1.0-dev.1"

type Profile string

const (
	HranaHTTP      Profile = "hrana-http"
	HranaWebSocket Profile = "hrana-websocket"
	MySQL          Profile = "mysql"
	PostgreSQL     Profile = "postgresql"
	Git            Profile = "git"
)

var endpointID = regexp.MustCompile(`^ep-[0-7][0-9a-hjkmnp-tv-z]{25}$`)
var endpointDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)

// ParseEndpoint requires an Endpoint ID followed by its deployment DNS suffix.
// DNS case is normalized; URLs, aliases and port suffixes are rejected.
func ParseEndpoint(value string) (string, error) {
	if len(value) > 253 {
		return "", failure(Configuration, "invalid Endpoint", false)
	}
	value = strings.ToLower(value)
	id, domain, hasDomain := strings.Cut(value, ".")
	if !hasDomain || !endpointID.MatchString(id) || !endpointDomain.MatchString(domain) {
		return "", failure(Configuration, "invalid Endpoint", false)
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 {
			return "", failure(Configuration, "invalid Endpoint", false)
		}
	}
	return value, nil
}

// Token holds an opaque InstanceToken. Formatting never reveals its value.
// The caller remains responsible for the lifetime of the original input.
type Token struct{ value string }

func NewToken(value string) (*Token, error) {
	if value == "" || !httpguts.ValidHeaderFieldValue(value) {
		return nil, failure(Configuration, "invalid InstanceToken", false)
	}
	return &Token{value: value}, nil
}

func (Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "Token([REDACTED])") }

type Metadata struct {
	Endpoint  string
	Profile   Profile
	RequestID string
	AuthMode  string
}
