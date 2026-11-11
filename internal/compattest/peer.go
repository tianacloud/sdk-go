// Package compattest supplies a same-socket SOCKS preface for local TLS tests.
package compattest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

func Accept(conn net.Conn, endpoint string) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	var greeting [3]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting != [3]byte{5, 1, 0} {
		return errors.New("expected unauthenticated SOCKS5 greeting")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}
	want := append([]byte{5, 1, 0, 3, byte(len(endpoint))}, []byte(endpoint)...)
	want = append(want, 1, 187)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("SOCKS target must preserve Endpoint domain and logical port 443")
	}
	_, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

type Listener struct {
	net.Listener
	Endpoint string
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err := Accept(conn, l.Endpoint); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
