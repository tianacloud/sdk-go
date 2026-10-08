# Public SDK migration decisions

## Scope and baseline

Adapt the existing native Go CONNECT library for `github.com/tianacloud/sdk-go`.
Keep the root package `tiana` and its transport-only scope. The separately
authorized `auth` extraction below extends the module without changing CONNECT.
The original migration source baseline was
`5f459af7d74f9a1e0d689708359c0dd386032dbc`; its separate original checkout retains
private history. This public repository has a clean source-history root at
`94d680c` and does not inherit that private history. Authentication security
hardening starts from this public root on `codex/1747aaac/sdk-auth-security`.
Do not commit, push or publish without an explicit user request.

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

Persistence originally retained uncoordinated RMW and refresh; the security
hardening decision below supersedes that behavior. JSON/file paths remain
compatible, but built-in reads now require private owned regular files and
writers participate in a shared persistent lock. No directory fsync guarantee
is introduced. Performance for local reads remains O(file), bounded to 8 MiB.

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


## Shared authentication security hardening

Background: inherited CLI behavior allowed remote plaintext credentials,
untrusted error-body diagnostics, unsafe account reads, and concurrent refresh
or store RMW races that could erase rotated credentials or other origins.
Keep CredentialStore source compatibility and existing JSON/path formats.

Chosen design: require HTTPS except literal loopback IPs/localhost development;
never resolve hostnames to create an HTTP exception. Ordinary API/transport
error formatting contains only fixed status/allowlisted codes, while structural
recovery fields remain available without automatic printing. Reject unsafe
browser verification URLs and bound/control-filter login labels. This does not
claim arbitrary resource metadata is inherently non-secret.

Built-in account and InstanceToken persistence uses the existing bounded
NOFOLLOW/NONBLOCK reader, owned regular mode-0600 files, 8 MiB cap and private
owned mode-0700 directory. Lock a persistent adjacent .lock inode via flock;
validate owner, type, exact mode and single hardlink, never unlink on unlock.
Lock acquisition is cancellable and capped at 30 seconds. FileStore Save/Delete
and token Save lock complete RMW. FileStore refresh locks reload → network
rotation → save/delete; waiters recheck current credentials and reuse a newer
valid version. invalid_grant never deliberately deletes a changed version.
Logout shares this transaction; unlocked internal adapters prevent recursion.

Tradeoffs: all origins in one file serialize during low-frequency refresh
network I/O. Callers must supply network contexts/timeouts. Custom stores are
serialized only per Client and still require caller-owned cross-client/process
coordination. Built-in stores support Linux/macOS local flock filesystems;
others fail closed. The same-user account/ancestor path is a trusted boundary;
these locks cannot coordinate old binaries or hostile same-user writers.

Compatibility/rollback: JSON/file names and CredentialStore methods remain;
unsafe 0644/symlink files and remote HTTP are deliberately rejected. Persistent
.lock sidecars remain after use. Older writers ignore them and must never run
concurrently. Directory fsync and distributed atomic refresh are not provided;
a crash between server rotation and local persistence can require re-login.
Do not weaken these checks to restore unsafe legacy behavior.

Verification: deterministic independent-client refresh rotation and subprocess
refresh/write tests, cancellation, crash-released persistent inode, malformed
HTTP and API diagnostic canaries, structural recovery fields, safe URL/labels,
file/lock symlink/FIFO/public/hardlink/size checks, compatible legacy JSON,
race tests, vet and Linux compilation. Use only synthetic credentials/files.

## Legacy InstanceToken file expiration compatibility

A pre-SDK CLI stored expires_at as RFC3339 timestamp strings, including
9999-12-31T23:59:59.999Z for no expiry. The SDK extraction accepted only int64
Unix seconds and incorrectly rejected those otherwise valid private files.
Decode both forms only in the internal instanceTokenFile boundary; public
credential types and management API wire decoding remain unchanged. Map the
exact legacy no-expiry sentinel to -1 and floor finite timestamps to seconds
without extending validity. Reject malformed/negative legacy times so a date
before the epoch cannot become -1. Preserve the 30-second expiry skew and all
origin/tenant/instance/endpoint identity and private-file checks.

Lookup never writes or migrates files. A successful locked Save preserves all
credential records and atomically writes canonical integer expirations, as the
current SDK already does. This can normalize old string timestamps and cannot
be read by pre-SDK string-only writers; do not mix old clients with new clients.
No new schema or network calls. Decoding remains linear in the bounded 8 MiB
file; no credentials or parser excerpts may appear in diagnostics. Tests must
cover literal legacy records, finite/never/expired/skew cases, mixed-origin
read-modify-write, failed-save preservation, and shell's real token lookup.


## 2026-09-28: API origin and explicit token environment

Use TIANA_API_ORIGIN as the sole API-origin environment name wherever an
origin is loaded. TIANA_MGR_ORIGIN and TIANA_AUTH_ORIGIN are ignored; do not add
compatibility aliases. Explicit API constructor parameters remain available.
Remove TIANA_TOKEN_FILE and raw token-file credential readers. CLI connections
use explicit TIANA_TOKEN (presence is authoritative: empty/malformed fails),
otherwise the selected saved account access token. SDK examples use TIANA_TOKEN;
library constructors continue to accept explicit token values. Never log tokens.
Account credential persistence and refresh locking are separate from raw token
file input and remain intact. No on-disk schema, network protocol or transaction
semantics change. Old environment names deliberately stop working without a
migration fallback. Rollback requires reverting code/docs together.

TIANA_PENDING_COMMAND_FILE, TIANA_CREDENTIALS_FILE and TIANA_GATEWAY_ADDRESS are
under review only; this change does not remove them or pending-operation state.
Keep bounded token validation, existing credential file protections, and explicit
SDK dial overrides. Verify retired names cannot override current configuration,
empty tokens fail closed, saved accounts still work, and runnable SDK examples
accept TIANA_TOKEN without reading a raw token file. No extra network round trips
or file reads may be introduced by environment resolution.


## 2026-09-28: one Gateway address environment name

User requires TIANA_GATEWAY_ADDRESS for example/launcher TCP overrides.
TIANA_DIAL_ADDRESS, TIANA_GATEWAY_HOST and TIANA_GATEWAY_PORT are removed names,
not fallback aliases. Existing explicit SDK Config.DialAddress / gateway options
retain their API names. No implicit environment reads are added to core SDKs.
Endpoint continues to determine TLS SNI, hostname verification and CONNECT
identity. Override only the physical TCP destination, never certificate checks.

Examples consume host:port, with bracketed IPv6. Node example adapters require a
canonical decimal port 1-65535 and reject URLs, credentials, paths and malformed
addresses without echoing the input. Keep these adapters in packaged examples;
do not introduce a public library API for environment parsing. This changes no
wire or storage format, database semantics, retry policy or connection ownership;
parsing adds only bounded work proportional to address input before dialing.
No migration shim: update launch environments, revert code/docs together if needed.
Verify IPv4/hostname/IPv6 parsing, malformed input rejection, installed examples,
and a real TLS/CONNECT exchange with conflicting removed variables present.


## Type-independent data Token authorization

Token scope is independent of instance engine and business channel. Endpoint,
Instance, Group and Tenant credentials may authorize SQLite, Git or Web when
valid and their scope covers the target. Web publication/control still requires
an authenticated credential even when resource reads are anonymous; do not add
an instance-kind whitelist. Preserve expiry, revocation, owner revisions, quota,
instance enablement and protocol checks. Site/project owner/admin policies and
MGR session/tenant/role checks remain separate from data authorization.

CLI Web publication/status uses the same explicit TIANA_TOKEN / TIANA_TOKEN_FILE
precedence as other connections, otherwise the pinned account's access token.
It never reads local instance-token caches or retries with alternate credentials.
The account still resolves MGR project metadata. Unknown publication outcomes
retain their identity/archive and are never automatically replayed. No wire,
schema, token issuance, storage or Gateway–Agent version changes are involved.
This current decision supersedes earlier instance-only Web publication and
account-credentials-never-reach-Gateway guidance.
