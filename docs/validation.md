# Validation and source distribution

## Local checks

Run from the module root with Go 1.25 or newer, Python 3 and Bash:

```sh
go test -race ./...
go vet ./...
python3 scripts/check-public-source.py
bash scripts/consumer-smoke.sh
```

Go dependencies come from public modules. No deployment, real tokens, private
DNS, or business database is needed. `TestConsumerEcho` is enabled by the smoke
script using a separately built executable; ordinary unit runs skip it.

The suite covers TLS hostname/trust/ALPN, CONNECT success barriers, sensitive
HPACK headers, explicit deployment names, duplex bytes/flow control,
half-close, cancellation/deadlines, error metadata, limits, and concurrent
stream ordering. Regression tests cover queue-full deadlines and updates,
flow-credit restoration, sibling isolation, and cancellation before HEADERS.

The public distribution manifest hashes its listed artifacts and itself
(with the manifest digest replaced by 64 zeroes). Changes to artifacts must
be reviewed and their manifest hashes regenerated; deleting integrity checks
is not an acceptable update procedure.

## Pinned Gateway interoperability

The opt-in harness targets Gateway commit
`9f5aa69b24aa6e04112baaf8d1e17c0639fd293b`. Supply a clean checkout of that
revision; the runner refuses a different HEAD or a dirty tree. It never
fetches private sources or credentials. Rust/Cargo, Go, Python 3, Bash and
access to the public dependency registries are required.

```sh
python3 scripts/test-gateway.py /absolute/path/to/gateway-checkout
```

The runner builds a local fixture with path dependencies on Gateway crates.
It copies the Gateway lockfile for dependency resolution, uses the SDK's
synthetic TLS identity, binds only loopback, and cleans its temporary files
and server process on exit. Standard Cargo/Go caches follow their environment
variables. Source checkouts remain unchanged.

Real Gateway ingress, TLS/H2, orchestration and relay serve SDK tunnels for
all five profiles, both anonymous and authenticated. Tests check server-first
bytes, 360,448-byte binary echoes, the post-END_STREAM tail, cancellation
isolation and bounded error mapping (including all three quota reasons and
non-retryability). An independent consumer executable also runs against it.
Control authorization, locator and the echo Agent are synthetic. Injected
service refusals exercise the real HTTP mapping, not the production cause of
each failure. Wrong-token handling is provided by the fixture adapter. This
does not validate real Control token refresh, Redis tenant admission,
Agent/database behavior, or transactions.

To run only Go checks against an already running equivalent fixture:

```sh
TIANA_GATEWAY_FIXTURE=/absolute/path/to/fixture \
  go test -race -tags=integration -run TestGatewaySnapshot -count=1 -v .
```

`ready.json` records the pinned `gateway_commit`, complete `endpoint`,
`anonymous_address`, `token_address`, greeting/tail and refusal listener
addresses used by the integration test. It also supplies
`fixtures/gateway.pem` and `fixtures/synthetic-token.txt`. Missing fixture
configuration fails explicitly; ordinary Go tests require no Gateway source.

## Export and review a public source snapshot

```sh
python3 scripts/export-source.py .artifacts/public-source
python3 scripts/check-public-source.py .artifacts/public-source
```

The destination must be empty. Export includes current tracked files and
non-ignored untracked files, including pending changes; review the file list
before release. Git metadata, prior commits, and local build artifacts are
excluded. Symlinks are rejected. The hostname scanner checks all snapshot
files and decoded PEM blocks, printing only filenames on failure. It is a
focused hostname check, not a general-purpose secret detector; inspect the
final snapshot and any added assets before publication.

Initialize any new public history from the reviewed snapshot. Do not push
private historical commits or old tags as part of the migration. Preserve
private provenance outside the public repository. The existing development
version is not permission to reuse an old tag for different source.

After publication, verify from a fresh consumer module **without replace**:

```sh
go mod init example.com/tiana-release-check
go get github.com/tianacloud/sdk-go@<published-version>
go list -m github.com/tianacloud/sdk-go
```

Build and run a representative consumer against the intended deployment
before declaring a public release validated.
