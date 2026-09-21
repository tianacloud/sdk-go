# Public SDK migration decisions

## Scope and baseline

Adapt the existing native Go CONNECT library for `github.com/tianacloud/sdk-go`.
Keep the root package `tiana` and its transport-only scope. The separately
authorized `auth` extraction below extends the module without changing CONNECT. The baseline
is `5f459af7d74f9a1e0d689708359c0dd386032dbc`. Do not commit or publish without
an explicit user request. This checkout retains private history for review;
only a scanned source snapshot is suitable for a new public history.

## Endpoint identity

Require an explicit deployment hostname; reject bare Endpoint IDs and remove
the default suffix constant. DNS case normalization remains, with 63-byte
label / 253-byte hostname limits. SNI and CONNECT authority bind to this
hostname with logical port 443. DialAddress only overrides the physical TCP
address. TLS 1.3, h2, certificate verification, and caller-provided roots remain.
This intentionally changes pre-release callers that passed bare IDs or used
the old suffix constant. Migrate them to the hostname supplied by their
deployment. No discovery request or synchronous control-plane dependency is
added to the data path. Rollback requires reverting callers and SDK together;
never reintroduce a private default into a public artifact.

## Stream ordering and bounded cancellation

Serialize stream allocation and the initial HEADERS write for each physical
connection, but release the ordering gate before waiting for the response.
Gate waits honor caller cancellation and session closure. Streams canceled
before their HEADERS start must not emit an RST_STREAM on an idle stream.
Canceled opened streams queue resets separately so Close/cancel cannot block
behind a full DATA queue. The writer drains pending resets before more DATA;
no goroutine is created for each reset. All queues and stream state remain
bounded by the writer and concurrent stream limits.

Write deadlines apply while waiting to enqueue, including deadline changes.
A request that has not entered the writer queue can return a deadline error
without terminating the stream, after restoring both reserved windows. Once
queued or writing, a timeout terminates the stream because its byte outcome
is uncertain. Reservation ownership and payload disposal transfer exactly
once from sender to writer at enqueue. Preserve sibling streams, half-close,
commit metadata, and the no-automatic-replay invariant.

## Public test assets and distribution

Keep a self-contained CONNECT conformance subset under conformance/v1, with
its own public identity, documented derivation, and recomputed hashes. Do not
claim byte identity with earlier assets. Use only reserved example/test DNS
names in fixtures. Generate fresh synthetic TLS keys/certificates with the
checked-in generator; keys are for tests only and are not trust material for
any deployment. Do not modify specification or control repositories.

Consumer smoke validates the current source snapshot by default, including
uncommitted migration changes. A separate consumer module builds the echo
example; it can run against a local synthetic TLS/H2 echo server without
private services. Optional external Gateway validation remains separate.
Public installation without replace can only be verified after publication.

## Validation and operational boundaries

Require regression tests for concurrent CONNECT ordering, canceled initial
HEADERS, queue-full deadlines and deadline updates, flow-credit restoration,
and sibling isolation. Run race, vet, formatting, the Go 1.25 minimum,
consumer smoke and public snapshot scans (including decoded certificates).
Retain per-stream request IDs and bounded error metadata; do not log tokens
or opaque tunnel data. No database persistence format, transaction semantics,
or server wire protocol changes are introduced. Tests use synthetic byte
streams, not production databases. Throughput and full deployed Gateway /
Agent / App interoperability need their own measurements; do not claim them
from unit tests.

## Gateway alignment (9f5aa69)

The pinned Gateway implements five database profile names. Add MySQL,
PostgreSQL and Git constants without interpreting opaque application bytes or
adding database drivers. Preserve the existing Hrana constants and the TLS,
SNI/authority, success barrier, flow control and no-replay invariants.
Fetch authority ports are a separate Gateway API; CONNECT continues to use
logical port 443. Token authorization caches and refresh stay server-side.

Expose QUOTA_EXCEEDED via the existing bounded Error.Code and HTTP 403.
Retain the error-body discard policy, so compute/storage reason is available
through server observability rather than a new SDK body parser. No retry is
implied by quota failure, even with a retry hint. This adds no buffering or
hot-path work beyond profile/code comparisons and changes no storage format.
Reverting these additions makes new profiles unsupported again; existing
Hrana clients remain source compatible.

Require five-profile wire/duplex tests, quota nonretry tests and a pinned
real Rust ingress/relay fixture. Its Control/locator/Agent doubles must be
identified as such; do not claim production token refresh, tenant admission
or database transaction validation. The external source is clean and read-only.

## Shared CLI authentication extraction

User requested moving CLI local authentication into SDK. Source CLI baseline is
`d990091f2f70a981d8cd746e8d6047f3dde0959c`. Expose a separate auth package for
MGR transactions/login, account refresh/logout/whoami, authenticated JSON
requests and account/InstanceToken file stores. Keep resource models, commands,
pending intent storage, compiled deployment origin and build TLS policy in CLI.
Do not add a dependency on CLI, a private default origin, or implicit local auth
into the root CONNECT package. SDK constructors do not read/create files.

Preserve XDG/home resolution, JSON keys and fields, per-origin account isolation,
Unix-second token expiry and -1 sentinel, lookup ordering/30s skew/tenant checks,
and existing 401-only refresh retry. A mutation needs its original idempotency
key and immutable payload. File capability lookup must follow MGR authorization;
account credentials must never reach Gateway. Do not introduce auto-creation,
rotation, alternate-token retry, SQL replay, or transaction/storage changes.

This is a behavior-preserving extraction, except formatting now redacts secret
values and the public SDK has no compiled deployment/default TLS bypass policy.
JSON encoding remains compatible. CLI's deployment wrapper supplies its existing
policy. Existing clients/binaries can read the same files for rollback; unresolved
pending operations stay in CLI. No format rewrite or user credential access is
part of validation. Follow current CLI file persistence (which supersedes the
older specification's keychain preference), not historical spec storage defaults.

Persistence retains file fsync + same-directory rename, parent chmod0700, file
0600, no parent-directory fsync and no RMW/refresh locking across instances or
processes. Explicitly document external serialization and possible lost updates;
do not imply stronger durability. InstanceToken lookup is bounded 8MiB and
Linux/macOS-only secure file opening; account reads/writes preserve existing
behavior. Performance adds no network calls, and local lookup remains O(file).

Validate legacy literal files, SDK-only login/refresh/logout/401 behavior,
privacy/TLS, origin precedence/no default and constructor no-I/O, CLI unchanged
business tests, race/vet, native/Linux builds and independent public consumers.
SDK publication must precede a release of CLI depending on this new package;
local validation uses only a session-scoped workspace/replace outside repos.

## Credential redirect and value-formatting fixes

The release security review reproduced refresh JSON forwarding across origins
and HTTPS-to-HTTP redirects, and copied Token values leaking through fmt.
Reject all automatic MGR redirects by copying the supplied/default http.Client
and setting CheckRedirect to ErrUseLastResponse. Return the original 3xx through
APIError without replay or credential replacement. Preserve caller transport,
timeout and jar; do not mutate the caller/global client. Custom RoundTrippers
are trusted code and remain responsible for their own network behavior.

This deliberately tightens the extracted CLI behavior: deployments using HTTP
redirects must configure their final MGR origin. No new opt-out or public API
is added. Existing 401 refresh behavior and file/wire formats remain unchanged.
Rollback restores the vulnerabilities; do not restore redirects for convenience.
No new network requests, persistent state, goroutines or hot-path buffering are
introduced. Add coverage for 301/302/303/307/308, same/cross origin, TLS downgrade,
custom redirect policies, unchanged stores and caller client ownership.

Use a value-receiver Token formatter so both values and pointers redact, including
values in exported struct fields, slices, arrays and maps. JSON/storage/token
encoding is unchanged; the original input string remains caller-owned. Test all
common fmt verbs and nil pointers. Require SDK race/vet and CLI regression checks.
