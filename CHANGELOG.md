# Changelog

## Unreleased

- Add an explicit `outbound.Policy` for HTTP/HTTPS CONNECT and SOCKS5 TCP proxies,
  with scheme-specific selection, `AllProxy` fallback and `NoProxy` matching.
  Both SOCKS schemes resolve target hostnames at the proxy. The SDK does not
  read proxy environment variables; callers supply configuration explicitly.
- Add `Config.Network` to Gateway and fetch clients, forward it to native
  resource requests, and expose outer proxy failures separately from Gateway
  status. Preserve verified target TLS, bounded setup and no replay/fallback.
- Add Gateway `Config.Port` for the logical network destination and proxy bypass
  matching; CONNECT authority remains `Endpoint:443`. Nil Network and an empty
  Port retain prior defaults. The added exported struct fields require updates
  to external unkeyed struct literals; keyed configurations remain compatible.

- Reject automatic MGR HTTP redirects, including caller-provided redirect policy,
  to prevent credential body replay. Configure the final MGR address directly.
- Redact copied InstanceToken values and tokens inside formatted containers.

- Extract CLI-compatible account authentication and local credential stores into
  `auth`, preserving existing file paths/formats and separating deployment defaults.
  Redact credential-bearing values during formatting.

- Align with Gateway `9f5aa69`: add MySQL, PostgreSQL and Git CONNECT profiles,
  preserve non-retryable `403/QUOTA_EXCEEDED`, and provide a pinned Rust
  Gateway interoperability harness.

- Move imports to `github.com/tianacloud/sdk-go`, retaining package `tiana`.
- Require explicit deployment hostnames and enforce DNS length limits; remove
  the exported default Endpoint suffix. Bare Endpoint IDs are no longer valid.
- Replace deployment-specific documentation, conformance assets and synthetic
  test certificates with a self-contained public distribution.
- Order concurrent CONNECT stream opening; avoid resets for unopened streams.
- Honor write deadlines and updates while waiting for queue space, restore
  unsubmitted flow credit, and prevent canceled streams from blocking on resets.
- Validate current source in a separate consumer module with a local echo peer.
- Add CI and source export/hostname checks. No public release is implied here.
