# Explicit outbound proxies

The `outbound` package provides one immutable routing policy for HTTP clients
and native Gateway streams. It supports HTTP CONNECT, HTTPS CONNECT and SOCKS5
TCP proxies, with Basic or SOCKS username/password authentication. It does not
read environment, credentials or files, and has no PAC or system discovery.

```go
policy, err := outbound.New(outbound.Config{
    AllProxy: "socks5h://127.0.0.1:1080",
    NoProxy: "localhost,127.0.0.1,::1",
})
if err != nil { return err }
client, err := tiana.NewClient(tiana.Config{
    Endpoint: endpoint,
    Network: policy,
})
```

Use the same policy as `fetch.Config.Network` for publication and native resource
clients. `auth.Config.HTTPClient` remains the injection point for management
HTTP: use a separate `http.Transport` with `Proxy` calling policy.ProxyForURL.
Do not also install a proxying DialContext underneath that HTTP transport.

Routing first bypasses logical loopback targets and NoProxy matches, then uses
HTTPProxy or HTTPSProxy for the URL scheme, then AllProxy, otherwise direct.
Every nonempty proxy setting is validated at construction, even if shadowed.
HTTPProxy never serves as an HTTPS fallback. CGI protection applies to HTTPProxy
when CGI is set. Returned proxy URLs are independent copies.

Proxy URLs accept http, https, socks5 and socks5h. Missing ports default to 80,
443 and 1080 respectively. Both SOCKS schemes use proxy-side target DNS, matching
Go's HTTP Transport; SOCKS4, BIND and UDP are unsupported. Explicit SOCKS credentials
require a nonempty decoded username and password of at most 255 bytes each.
Proxy input is bounded to 8 KiB per URL and 16 KiB for NoProxy. Config formatting
redacts values. Never print a selected proxy URL containing credentials.

DialTunnel returns a connected target byte stream after any proxy handshake.
The caller owns target TLS, application authorization, I/O cancellation and
closing the connection. Physical DialAddress overrides change only the dial or
outer proxy CONNECT destination; routing uses the logical URL. Literal loopback
overrides always dial directly. A local proxy address does not itself bypass
proxy routing. Target DNS is passed to the proxy without local resolution.
Gateway Config.Port specifies the logical network port, default 443, for its
default dial target and NO_PROXY matching. An explicit DialAddress overrides
the physical target only; inner Gateway authority always remains Endpoint:443.

Gateway retains its original verified TLS 1.3 and h2 identity. HTTPS proxies are
separately verified against their own hostname and ProxyRootCAs, or system roots
when nil. A policy clones supplied proxy roots. No proxy handshake contains a
Tiana bearer credential. Basic over an HTTP proxy and SOCKS username/password
are not encrypted by the target's inner TLS.

Use a bounded context for DialTunnel. Proxy TCP, TLS and CONNECT share that
deadline; success clears setup deadlines before handoff. Gateway and fetch apply
their existing setup budgets. Proxy establishment performs one attempt, without
direct fallback, authentication retries or operation replay. HTTP CONNECT heads
are bounded to 16 KiB and 64 fields, and prefetched tunnel bytes are preserved.

`outbound.Error` exposes safe classifications, optional proxy HTTP status and
context cancellation/deadline sentinels, without raw peer errors or addresses.
Gateway uses `tiana.Proxy` and ProxyStatus for outer proxy failures; its Status
and Code remain Gateway metadata. fetch preserves errors.Is(err, fetch.ErrTransport)
and may also wrap outbound.Error. A proxy success is not a Gateway acceptance or
proof of application completion.

Policies are concurrent and own no sockets or pools. Each Gateway/fetch/HTTP
client keeps its own credential and connection ownership. Nil Network retains
the previous direct path, including no implicit environment reads. There are no
wire or local persistence changes; removing injection rolls back proxy access.
