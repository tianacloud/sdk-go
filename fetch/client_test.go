package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEncodedHTTPAndControlSelection(t *testing.T) {
	encoded := []byte{0x1f, 0x8b, 0x08, 0, 1, 2, 3}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cache-Control") != "no-store" || r.URL.Path != "/v1/fetch" || r.Header.Get("Authorization") != "Bearer tia_0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
			t.Error("outer authorization")
		}
		var head [10]byte
		_, _ = io.ReadFull(r.Body, head[:])
		if string(head[:4]) != "TFQ1" {
			t.Error("frame magic")
		}
		meta := make([]byte, binary.BigEndian.Uint32(head[6:]))
		_, _ = io.ReadFull(r.Body, meta)
		var request metadata
		if json.Unmarshal(meta, &request) != nil || request.Protocol != "tiana-http" || request.PathQuery != "/_tiana/web/publish" || request.Headers[0].Value != "gzip" {
			t.Error("channel/header")
		}
		input, _ := io.ReadAll(r.Body)
		if string(input) != "archive" {
			t.Error("upload")
		}
		response, _ := canonicalJSON(struct {
			Version int      `json:"metadata_version"`
			ID      string   `json:"request_id"`
			Status  int      `json:"status"`
			Text    string   `json:"status_text"`
			Headers []Header `json:"headers"`
			Length  int      `json:"body_length"`
		}{1, request.RequestID, 200, "OK", []Header{{"content-encoding", "gzip"}}, len(encoded)})
		copy(head[:4], "TFS1")
		binary.BigEndian.PutUint32(head[6:], uint32(len(response)))
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(head[:])
		w.Write(response)
		w.Write(encoded)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, e := NewClient(Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test", DialAddress: server.Listener.Addr().String(), RootCAs: roots, Token: "tia_0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	// Test-only transport retains certificate verification against the generated certificate.
	client.transport.TLSClientConfig.ServerName = "example.com"
	result, e := client.Do(context.Background(), Request{Method: "PUT", PathQuery: "/_tiana/web/publish", Body: bytes.NewBufferString("archive"), BodyLength: 7, Headers: []Header{{"accept-encoding", "gzip"}}})
	if e != nil {
		t.Fatal(e)
	}
	defer result.Body.Close()
	got, e := io.ReadAll(result.Body)
	if e != nil || !bytes.Equal(got, encoded) || result.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("response: %v %v", got, e)
	}
}
func TestFrameBodyIntegrityAndBounds(t *testing.T) {
	for _, tc := range []struct {
		body   string
		length int64
		valid  bool
	}{{"abc", 3, true}, {"ab", 3, false}, {"abcd", 3, false}, {"", 0, true}, {"x", 0, false}} {
		remaining := tc.length
		b := &boundedBody{body: io.NopCloser(bytes.NewBufferString(tc.body)), remaining: &remaining}
		_, e := io.ReadAll(b)
		if (e == nil) != tc.valid {
			t.Errorf("%+v: %v", tc, e)
		}
	}
	for _, h := range []Header{{"host", "x"}, {"authorization", "Bearer tia_0secret"}, {"x-test", "bad\r\nheader"}, {"Accept-Encoding", "gzip"}} {
		if validHeader(h) {
			t.Error("accepted forbidden header")
		}
	}
	if !validHeader(Header{"accept-encoding", "gzip, br"}) {
		t.Error("encoding blocked")
	}
}

// This literal vector does not use the client's encoder or decoder helpers.
func TestLiteralFramingAndHeadIntegrity(t *testing.T) {
	const requestJSON = `{"metadata_version":1,"request_id":"golden","protocol":"tiana-http","method":"HEAD","path_query":"/a?x=1&y=2","headers":[],"body_length":0}`
	const responseJSON = `{"metadata_version":1,"request_id":"golden","status":200,"status_text":"OK","headers":[{"name":"content-encoding","value":"gzip"},{"name":"content-length","value":"42"}],"body_length":0}`
	for _, trailing := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "trailing-body"}[trailing], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				expected := append([]byte{'T', 'F', 'Q', '1', 0, 0, 0, 0, 0, byte(len(requestJSON))}, []byte(requestJSON)...)
				if !bytes.Equal(raw, expected) {
					t.Errorf("noncanonical request frame: %q", raw)
				}
				w.Header().Set("Content-Type", mediaType)
				w.Header().Set("Cache-Control", "no-store")
				frame := append([]byte{'T', 'F', 'S', '1', 0, 0, 0, 0, 0, byte(len(responseJSON))}, []byte(responseJSON)...)
				if trailing {
					frame = append(frame, 'x')
				}
				_, _ = w.Write(frame)
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			c, err := NewClient(Config{Endpoint: "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.example.test", DialAddress: server.Listener.Addr().String(), RootCAs: roots, Token: "tia_0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.transport.TLSClientConfig.ServerName = "example.com"
			res, err := c.Do(context.Background(), Request{RequestID: "golden", Method: "HEAD", PathQuery: "/a?x=1&y=2"})
			if trailing {
				if err == nil {
					res.Body.Close()
					t.Fatal("accepted HEAD trailing body")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.Header.Get("Content-Length") != "42" || res.Header.Get("Content-Encoding") != "gzip" {
				t.Fatal("representation metadata lost")
			}
		})
	}
}
