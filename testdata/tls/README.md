# Synthetic TLS fixtures

These self-signed certificates and public test keys are generated specifically
for this SDK. Their names use the reserved `.test` namespace; they do not
identify deployment infrastructure. Never use these keys or trust roots in a
real deployment.

From the module root, regenerate with:

```sh
go run ./testdata/tls/generate.go
go test -race ./...
```

The generator uses fresh random P-256 keys and serial numbers. Certificates
are valid from 2020 to 2120 to avoid date-sensitive tests. `endpoint` and
`wildcard` verify positive hostname cases; `wrong` verifies hostname rejection;
`unrelated` is a separate trust root with no corresponding server private key.
Generation changes fixture bytes and should be reviewed as such.
