package compattest

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"testing"
	"time"
)

// ResolveLoopback maps only the fixture Endpoint without changing host DNS.
func ResolveLoopback(t *testing.T, endpoint string) {
	previous := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = previous })
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			wire := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, wire); err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(wire); err != nil {
				return
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Name.String() != endpoint+"." {
					t.Error("unexpected DNS target")
					return
				}
				if q.Type == dnsmessage.TypeA {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			wire, err := reply.Pack()
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
			server.Write(append(size[:], wire...))
		}()
		return client, nil
	}}
}
