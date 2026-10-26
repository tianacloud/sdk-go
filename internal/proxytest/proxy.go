// Package proxytest provides synthetic, local-only proxy peers for SDK tests.
package proxytest

import (
	"bufio"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

type Request struct {
	Address, Authorization, Username, Password string
	AddressType                                byte
}
type Proxy struct {
	URL         string
	Roots       *x509.CertPool
	Target      string
	RequireAuth bool
	mu          sync.Mutex
	requests    []Request
	conns       []net.Conn
	wg          sync.WaitGroup
}

func (p *Proxy) Requests() []Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Request(nil), p.requests...)
}
func (p *Proxy) record(r Request) { p.mu.Lock(); p.requests = append(p.requests, r); p.mu.Unlock() }
func (p *Proxy) track(c net.Conn) { p.mu.Lock(); p.conns = append(p.conns, c); p.mu.Unlock() }
func (p *Proxy) close() {
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
}

func HTTP(t *testing.T, target string, secure bool) *Proxy {
	t.Helper()
	p := &Proxy{Target: target}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(Request{Address: r.Host, Authorization: r.Header.Get("Proxy-Authorization")})
		if r.Method != http.MethodConnect {
			w.WriteHeader(400)
			return
		}
		if p.RequireAuth && r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			w.WriteHeader(407)
			return
		}
		upstream, err := net.Dial("tcp", p.Target)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		p.track(upstream)
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		p.track(client)
		p.wg.Add(1)
		defer p.wg.Done()
		defer client.Close()
		defer upstream.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		relay(client, rw, upstream)
	}))
	if secure {
		s.StartTLS()
	} else {
		s.Start()
	}
	p.URL = s.URL
	if secure {
		p.Roots = x509.NewCertPool()
		p.Roots.AddCert(s.Certificate())
	}
	t.Cleanup(func() { p.close(); s.Close(); p.wg.Wait() })
	return p
}

func SOCKS(t *testing.T, target string, authenticated bool) *Proxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{URL: "socks5h://" + l.Addr().String(), Target: target, RequireAuth: authenticated}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.track(c)
			p.wg.Add(1)
			go func() { defer p.wg.Done(); defer c.Close(); p.socks(c) }()
		}
	}()
	t.Cleanup(func() { l.Close(); p.close(); p.wg.Wait() })
	return p
}

func (p *Proxy) socks(c net.Conn) {
	r := bufio.NewReader(c)
	var head [4]byte
	if _, err := io.ReadFull(r, head[:2]); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	request := Request{}
	if p.RequireAuth {
		_, _ = c.Write([]byte{5, 2})
		if _, err := io.ReadFull(r, head[:2]); err != nil || head[0] != 1 {
			return
		}
		user := make([]byte, int(head[1]))
		if _, err := io.ReadFull(r, user); err != nil {
			return
		}
		n, err := r.ReadByte()
		if err != nil {
			return
		}
		pass := make([]byte, int(n))
		if _, err := io.ReadFull(r, pass); err != nil {
			return
		}
		request.Username, request.Password = string(user), string(pass)
		if request.Username != "user" || request.Password != "pass" {
			p.record(request)
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0})
	}
	if _, err := io.ReadFull(r, head[:]); err != nil || head[0] != 5 || head[1] != 1 {
		return
	}
	var host string
	request.AddressType = head[3]
	switch head[3] {
	case 3:
		n, err := r.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	case 1, 4:
		n := 4
		if head[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	if _, err := io.ReadFull(r, head[:2]); err != nil {
		return
	}
	request.Address = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(head[:2]))))
	p.record(request)
	upstream, err := net.Dial("tcp", p.Target)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	p.track(upstream)
	defer upstream.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	relay(c, r, upstream)
}

func relay(client net.Conn, reader io.Reader, upstream net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
