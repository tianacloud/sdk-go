package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/proxy"
)

// DialTunnel performs exactly one direct or proxy establishment attempt. The
// caller's context must bound setup; target TLS and subsequent I/O belong to
// the caller. It never sends application credentials or retries a failed dial.
func (p *Policy) DialTunnel(ctx context.Context, target Target) (net.Conn, error) {
	if ctx == nil {
		return nil, configError("")
	}
	address, err := targetAddress(target.URL)
	if err != nil {
		return nil, err
	}
	if target.DialAddress != "" {
		host, port, e := net.SplitHostPort(target.DialAddress)
		if e != nil || !validHost(host) || !validPort(port) {
			return nil, configError("")
		}
		address = target.DialAddress
		if loopback(host) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
	}
	selected, err := p.ProxyForURL(target.URL)
	if err != nil {
		return nil, err
	}
	if selected == nil {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if selected.Scheme == "socks5" || selected.Scheme == "socks5h" {
		d, e := proxy.FromURL(selected, &net.Dialer{})
		if e != nil {
			return nil, configError("")
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, configError("")
		}
		conn, e := cd.DialContext(ctx, "tcp", address)
		if e != nil {
			return nil, contextError(ctx, Connect)
		}
		return conn, nil
	}
	return p.httpConnect(ctx, selected, address)
}

func (p *Policy) httpConnect(ctx context.Context, selected *url.URL, address string) (_ net.Conn, resultErr error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", selected.Host)
	if err != nil {
		return nil, contextError(ctx, Connect)
	}
	owned := conn
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = owned.Close(); close(done) })
	detached := false
	detach := func() {
		if !detached {
			if !stop() {
				<-done
			}
			detached = true
		}
	}
	defer func() {
		detach()
		if resultErr != nil {
			_ = owned.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if conn.SetDeadline(deadline) != nil {
			return nil, contextError(ctx, Connect)
		}
	}
	if selected.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: selected.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: p.proxyRoots, NextProtos: []string{"http/1.1"}})
		if tlsConn.HandshakeContext(ctx) != nil {
			return nil, contextError(ctx, TLS)
		}
		conn = tlsConn
	}
	request := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if selected.User != nil {
		password, _ := selected.User.Password()
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(selected.User.Username()+":"+password)) + "\r\n"
	}
	request += "\r\n"
	if _, err := io.Copy(conn, strings.NewReader(request)); err != nil {
		return nil, contextError(ctx, Connect)
	}
	reader := bufio.NewReaderSize(conn, 4096)
	status, err := responseHead(reader)
	if err != nil {
		return nil, contextError(ctx, Protocol)
	}
	if status != 200 {
		kind := Connect
		if status == 407 {
			kind = Auth
		}
		return nil, &Error{Kind: kind, ProxyStatus: status}
	}
	// Detach setup cancellation before handing the connection to its owner.
	detach()
	if ctx.Err() != nil {
		return nil, contextError(ctx, Connect)
	}
	if conn.SetDeadline(time.Time{}) != nil {
		return nil, &Error{Kind: Connect}
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// responseHead bounds allocation while reading, rather than checking the size
// after an unbounded HTTP parser has consumed a malicious proxy response.
func responseHead(r *bufio.Reader) (int, error) {
	used := 0
	readLine := func() (string, error) {
		var line []byte
		for {
			part, err := r.ReadSlice('\n')
			used += len(part)
			if used > 16<<10 {
				return "", &Error{Kind: Protocol}
			}
			line = append(line, part...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil || len(line) < 2 || line[len(line)-2] != '\r' {
				return "", &Error{Kind: Protocol}
			}
			return string(line[:len(line)-2]), nil
		}
	}
	line, err := readLine()
	if err != nil {
		return 0, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || (parts[0] != "HTTP/1.0" && parts[0] != "HTTP/1.1") || len(parts[1]) != 3 || !safeText(line) {
		return 0, &Error{Kind: Protocol}
	}
	status, e := strconv.Atoi(parts[1])
	if e != nil || status < 200 || status > 599 {
		return 0, &Error{Kind: Protocol}
	}
	for fields := 0; ; fields++ {
		line, err = readLine()
		if err != nil {
			return 0, err
		}
		if line == "" {
			return status, nil
		}
		if fields >= 64 {
			return 0, &Error{Kind: Protocol}
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return 0, &Error{Kind: Protocol}
		}
	}
}
