# Changelog

## Unreleased

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
