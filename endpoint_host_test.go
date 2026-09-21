package tiana

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestDeploymentHostnameTLSAndAuthority(t *testing.T) {
	host := testEndpoint + ".db.dev.tiana.test"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	s := listenTest(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}, func(conn *tls.Conn) {
		if got := conn.ConnectionState().ServerName; got != host {
			t.Errorf("SNI = %q, want %q", got, host)
		}
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != host+":443" {
				t.Errorf("CONNECT target = %s %q", r.Method, r.Host)
			}
			echoHandler(w, r)
		})})
	})
	c := clientFor(t, s, func(cfg *Config) { cfg.Endpoint, cfg.RootCAs = host, roots })
	tunnel := connectFor(t, c, context.Background())
	readExact(t, tunnel, "HELLO")
	if _, err := tunnel.Write([]byte("deployment")); err != nil {
		t.Fatal(err)
	}
	readExact(t, tunnel, "deployment")
	wrongHost := clientFor(t, s, func(cfg *Config) {
		cfg.Endpoint, cfg.RootCAs = testEndpoint+".db.other.tiana.test", roots
	})
	if _, err := wrongHost.Connect(context.Background(), HranaHTTP); err == nil {
		t.Fatal("accepted certificate for a different deployment hostname")
	}
}
