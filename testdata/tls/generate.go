//go:build ignore

// Generate synthetic test certificates: go run ./testdata/tls/generate.go
// Run from the module root. These keys must never be used by a deployment.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	for _, fixture := range []struct{ name, host string }{
		{"endpoint", "ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test"},
		{"wildcard", "*.db.example.test"},
		{"wrong", "*.wrong.example.test"},
		{"unrelated", "*.db.example.test"},
	} {
		if err := generate(fixture.name, fixture.host); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func generate(name, host string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	root := filepath.Join("testdata", "tls")
	if err := os.WriteFile(filepath.Join(root, name+"_certificate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	if name == "unrelated" {
		return nil
	} // intentionally unrelated trust anchor only
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(private)
	return os.WriteFile(filepath.Join(root, name+"_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600)
}
