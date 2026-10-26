// Package outbound supplies explicit, immutable proxy routing for HTTP and
// byte-stream clients. It never reads process environment or credential files.
package outbound

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	MaxProxyBytes   = 8 << 10
	MaxNoProxyBytes = 16 << 10
)

// Config contains explicit proxy settings. All nonempty proxy values are
// validated, including values shadowed by a scheme-specific proxy. Root pools
// are cloned. Empty values mean unconfigured; ALL_PROXY is a fallback only.
type Config struct {
	HTTPProxy    string
	HTTPSProxy   string
	AllProxy     string
	NoProxy      string
	CGI          bool
	ProxyRootCAs *x509.CertPool
}

func (Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "outbound.Config([REDACTED])") }

// Target separates the logical URL used for routing from an optional physical
// host:port override. Neither supplies target TLS identity or credentials.
type Target struct {
	URL         *url.URL
	DialAddress string
}

func (Target) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "outbound.Target([REDACTED])") }

// Policy is safe for concurrent use. It owns no connection pools or sockets.
type Policy struct {
	selectProxy func(*url.URL) (*url.URL, error)
	proxyRoots  *x509.CertPool
	cgiHTTP     bool
}

func (Policy) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "outbound.Policy([REDACTED])") }

// New validates configuration without environment, filesystem or network I/O.
func New(c Config) (*Policy, error) {
	if len(c.NoProxy) > MaxNoProxyBytes {
		return nil, configError("NO_PROXY")
	}
	values := []*string{&c.HTTPProxy, &c.HTTPSProxy, &c.AllProxy}
	names := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
	for i, v := range values {
		if *v == "" {
			continue
		}
		u, err := parseProxy(*v)
		if err != nil {
			return nil, configError(names[i])
		}
		*v = u.String()
	}
	cgi := c.CGI && c.HTTPProxy != ""
	if c.HTTPProxy == "" {
		c.HTTPProxy = c.AllProxy
	}
	if c.HTTPSProxy == "" {
		c.HTTPSProxy = c.AllProxy
	}
	p := &Policy{selectProxy: (&httpproxy.Config{HTTPProxy: c.HTTPProxy, HTTPSProxy: c.HTTPSProxy, NoProxy: c.NoProxy}).ProxyFunc(), cgiHTTP: cgi}
	if c.ProxyRootCAs != nil {
		p.proxyRoots = c.ProxyRootCAs.Clone()
	}
	return p, nil
}

// ProxyForURL selects one proxy, or nil for direct routing. A returned URL is
// an independent copy. Selection never resolves DNS or falls back on error.
func (p *Policy) ProxyForURL(u *url.URL) (*url.URL, error) {
	if _, err := targetAddress(u); err != nil {
		return nil, err
	}
	if loopback(u.Hostname()) || p == nil || p.selectProxy == nil {
		return nil, nil
	}
	proxy, err := p.selectProxy(u)
	if err != nil {
		return nil, configError("HTTP_PROXY")
	}
	if proxy == nil {
		return nil, nil
	}
	if u.Scheme == "http" && p.cgiHTTP {
		return nil, configError("HTTP_PROXY")
	}
	copy := *proxy
	return &copy, nil
}

func parseProxy(raw string) (*url.URL, error) {
	if len(raw) > MaxProxyBytes || !safeText(raw) {
		return nil, configError("")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, configError("")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	port := ""
	switch u.Scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	case "socks5", "socks5h":
		port = "1080"
	default:
		return nil, configError("")
	}
	if !validHost(u.Hostname()) {
		return nil, configError("")
	}
	if u.Port() != "" {
		port = u.Port()
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, configError("")
	}
	if !validPort(port) {
		return nil, configError("")
	}
	if u.User != nil {
		name := u.User.Username()
		password, hasPassword := u.User.Password()
		if !safeText(name) || !safeText(password) || name == "" {
			return nil, configError("")
		}
		if u.Scheme == "socks5" || u.Scheme == "socks5h" {
			if !hasPassword || len(name) > 255 || len(password) == 0 || len(password) > 255 {
				return nil, configError("")
			}
		} else if strings.Contains(name, ":") {
			return nil, configError("")
		}
	}
	u.Host = net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	u.Path, u.RawPath = "", ""
	return u, nil
}

func targetAddress(u *url.URL) (string, error) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || !validHost(u.Hostname()) {
		return "", configError("")
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", configError("")
		}
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if !validPort(port) {
		return "", configError("")
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func validHost(host string) bool {
	return host != "" && len(host) <= 253 && safeText(host) && !strings.ContainsAny(host, " /\\@?#[]%") && (!strings.Contains(host, ":") || net.ParseIP(host) != nil)
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}

func safeText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func contextError(ctx context.Context, fallback Kind) error {
	if ctx.Err() != nil {
		return &Error{Kind: Canceled, cause: ctx.Err()}
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return &Error{Kind: Canceled, cause: context.DeadlineExceeded}
	}
	return &Error{Kind: fallback}
}
