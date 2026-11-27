# Changelog

## v1.3.1

- Preserve `412 / INSTANCE_DISABLED` on CONNECT and resource requests without retry.

## v1.3.0

- Add optional registration-source metadata to CLI authentication transactions.
  Callers provide `auth.Config.AcquisitionSource`; creation validates the source
  without reading environment variables or changing existing transaction state.

## v1.2.0-rc.1

- Add Function file clients for the resource owner's tenant root, an explicit
  Web directory and the request's Gateway-injected Web identity. Support List,
  Metadata, streamed GET/HEAD/Range, public file URLs, known-length PUT, Delete
  and Capabilities, with typed uncertain-write errors and no automatic replay.

## v1.1.1

- Use actual filesystem access for Linux/macOS credential stores and locks,
  including writable shared directories with a different owner.
- Preserve quota error codes and request IDs in Function and Vault diagnostics.

## Unreleased

- Add `wechatmini` for server-side WeChat code exchange, signed application
  sessions and verified request-context identities, with a native mini-program
  and Function demo. Application users are independent of platform accounts.

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
