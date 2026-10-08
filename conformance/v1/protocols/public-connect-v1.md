# Public CONNECT authority v1

This SDK test distribution describes the public client boundary. It is a
publicly adapted subset, not a byte-identical copy of an earlier distribution.

Clients use TLS 1.3, ALPN `h2`, and regular HTTP/2 CONNECT. An Endpoint is:

```text
<endpoint_id>.<deployment_dns_suffix>
endpoint_id = ^ep-[0-7][0-9a-hjkmnp-tv-z]{25}$
```

The deployment supplies its DNS suffix. The SDK requires the complete
hostname; bare IDs, URLs, credentials, paths, trailing dots and explicit
ports are rejected. DNS labels are at most 63 ASCII bytes and the hostname is
at most 253 bytes. DNS case is normalized to lowercase. Example hostnames in
this distribution use reserved `.test` names and do not identify a service.

TLS SNI and the CONNECT `:authority` hostname must be identical and name one
Endpoint. The logical authority port is 443. `Config.DialAddress` may change
the physical TCP target but never SNI, authority, or certificate validation.
One physical connection serves one Endpoint and one trust/credential context.

Requests contain `:method=CONNECT`, `:authority`, `tiana-tunnel-version=1`,
`tiana-database-protocol`, and a fresh `tiana-request-id`. The SDK supports
`hrana-http`, `hrana-websocket`, `mysql`, `postgresql`, and `git`. Optional `proxy-authorization` carries a
canonical InstanceToken with HPACK never-indexed encoding. No request DATA is
sent before the complete success response has been validated.

A successful response contains exactly `:status=200`,
`tiana-tunnel-version=1`, matching `tiana-request-id`, and `tiana-auth-mode`
(`TOKEN_REQUIRED` or `DISABLED`). DATA then carries opaque bytes. END_STREAM
half-closes its direction; RST_STREAM terminates only that stream. New stream
HEADERS are sent in ascending stream-ID order. GOAWAY stops new streams on
that connection and distinguishes excluded, unprocessed requests.

There is no automatic reconnect or operation replay. After success has been
observed, failures carry an unknown inner-session outcome. Clients may use
bounded pre-commit error metadata to decide whether to explicitly retry.

The Gateway quota refusal is HTTP 403 with `tiana-error-code=QUOTA_EXCEEDED`.
It is not retryable, even with a retry hint. This transport exposes the bounded
status/code headers and discards the JSON body, including quota reason.
Gateway token authorization caching/refresh is server-side and does not change
the client token grammar or introduce post-commit SDK replay.
