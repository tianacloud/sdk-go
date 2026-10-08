# Tiana Go SDK

**English** | [简体中文](README.zh-CN.md)

Native Go transport for Tiana v1 CONNECT, with module path
`github.com/tianacloud/sdk-go` with package name `tiana`. Requires Go 1.25 or
newer; licensed under Apache-2.0. The root package opens byte tunnels for Hrana
HTTP/WebSocket, MySQL, PostgreSQL and Git. It is not a `database/sql` driver or a SQL query API.

## Account authentication

The separate [`auth` package](docs/authentication.md) owns MGR login, refresh,
logout, account credentials and saved InstanceToken lookup, shared with the CLI.
It reads the existing `~/.config/tiana` files (or XDG_CONFIG_HOME) without a
format migration. Supply the MGR origin explicitly or through the documented
environment variables; no deployment origin is built into the SDK.
The root CONNECT client does not implicitly read these files or initiate login.
See the package guide for usage, authorization boundaries and store concurrency.

`Config.OnRequestID` receives each CONNECT identity before network I/O, including
failed handshakes. Callbacks may run concurrently; keep them brief. Callback
panics do not change the connection result. The same identity is available in
tunnel metadata and connection errors.

`auth.WithRequestID(ctx, id)` carries an existing logical request identity into
MGR calls, including their diagnostic callbacks and errors. Use a separate
context for each concurrent request. Calls without an inherited ID generate one.

`auth.Config.OnRequestID` receives the generated request ID before each MGR
network attempt, including successful requests. Keep this diagnostic callback
brief; a callback panic is contained. `auth.RequestIDOf(err)` retrieves the
identity associated with a request error without exposing credentials or response
bodies. A polling response that reports denied, expired or completed authorization
also retains its request ID; `errors.Is` still recognizes the corresponding
authentication transaction error.

MGR requires HTTPS except loopback development. Linux/macOS file stores use
owned private file modes and `flock`; Windows uses owner-only ACLs and
`LockFileEx`. All three reject unsafe files and coordinate refresh/writes across
processes with persistent locks on local filesystems. Custom stores require
caller-owned cross-client coordination.

MGR requests never follow HTTP redirects, including same-origin redirects and
caller-provided redirect policies. Configure the final MGR origin directly;
a 3xx response is returned as an APIError with its original status. Account
access/refresh tokens are separate from the InstanceTokens used by CONNECT.

## Installation

After a release is published to this repository:

```sh
go get github.com/tianacloud/sdk-go@latest
```

For an unpublished source candidate, use a local checkout explicitly:

```sh
go mod edit -require=github.com/tianacloud/sdk-go@v0.0.0
go mod edit -replace=github.com/tianacloud/sdk-go=/absolute/path/to/sdk-go
go mod tidy
```

`v0.0.0` is only a local replacement placeholder, not a published version.
The SDK User-Agent version is currently `0.1.0-dev.1`. See
[CHANGELOG.md](CHANGELOG.md) for unreleased changes; no public tag is implied.

## Open a tunnel

```go
package main

import (
    "context"
    "log"
    "os"

    tiana "github.com/tianacloud/sdk-go"
)

func main() {
    // Set TIANA_ENDPOINT to the complete hostname supplied by your deployment.
    cfg := tiana.Config{Endpoint: os.Getenv("TIANA_ENDPOINT")}
    if raw := os.Getenv("TIANA_TOKEN"); raw != "" {
        token, err := tiana.NewToken(raw)
        if err != nil { log.Fatal(err) }
        cfg.Token = token
    }
    client, err := tiana.NewClient(cfg)
    if err != nil { log.Fatal(err) }
    defer client.Close()

    // ctx owns establishment and the resulting tunnel's lifetime.
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    tunnel, err := client.Connect(ctx, tiana.HranaHTTP)
    if err != nil { log.Fatal(err) }
    defer tunnel.Close()
    // Pass tunnel (net.Conn) to a compatible Hrana HTTP transport.
}

```

`Config.Endpoint` requires a complete deployment hostname, for example
`ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test` (illustrative only), and
normalizes DNS case. Bare IDs, URLs and port suffixes are rejected. Supply the
actual hostname from your deployment's connection settings. SNI and CONNECT
authority use that hostname and logical port 443. `Config.DialAddress`
optionally changes only the physical TCP target.
`Config.RootCAs` replaces system trust roots when supplied; the SDK clones it.
TLS verification remains enabled, with TLS 1.3 and ALPN `h2` required.

Omit `Token` for an Endpoint whose policy permits anonymous access. Supplied
tokens are opaque credential strings. A token belongs to its Client;
different credentials or trust roots use separate Clients. Formatting Token,
Config, Client and Tunnel values redacts their contents, including copied Token
values and tokens in formatted containers. The root CONNECT package emits no logs.

`HranaHTTP`, `HranaWebSocket`, `MySQL`, `PostgreSQL` and `Git` select Gateway
profiles (`hrana-http`, `hrana-websocket`, `mysql`, `postgresql`, `git`, `tiana-http`). All carry
opaque bytes; the SDK provides the CONNECT transport. Authentication inside
the database protocol remains the caller's separate input.

## Stream behavior

- `Connect` returns after the complete, closed 200 header set is validated.
  It sends no request DATA before that barrier and preserves server-first data.
- `Write` applies stream and connection flow control. Concurrent readers and
  writers are supported, with multiple same-direction calls serialized.
- `CloseWrite` sends END_STREAM. Remote END_STREAM yields `io.EOF` after
  buffered data. The local write direction remains open; the peer may close
  it after its half-close grace period.
- `Close` cancels only its stream. Canceling the Connect context unblocks
  pending establishment, reads and writes; `errors.Is` recognizes
  `context.Canceled` and context deadlines. `Client.Close` closes all tunnels
  and waits for the physical readers/writers to exit.
- `SetReadDeadline`, `SetWriteDeadline` and `SetDeadline` affect that tunnel.
  Deadline errors implement `net.Error` and unwrap `os.ErrDeadlineExceeded`.
  A timeout while a frame is queued or being written terminates the stream
  because its byte outcome cannot be established. A flow-control or pre-enqueue wait timeout
  leaves the stream available after the deadline is changed; unsubmitted flow
  credit is restored. Enqueue waits also honor deadline updates.

One Client shares a connection across up to 32 concurrent streams by default;
`MaxStreams` permits 1–256. Each stream has a 65,535-byte unread DATA window
and writes frames of at most 16 KiB. Response headers are limited to 16 KiB
and 64 fields. Physical writes have the configured `ConnectTimeout` bound
(default 10 seconds); CONNECT responses default to 60 seconds. Canceling one
stream or receiving RST_STREAM preserves its siblings.

GOAWAY stops new streams on that connection. Streams at or below its last
accepted ID continue; excluded streams receive `Unprocessed` metadata. A
subsequent explicit `Connect` may establish a new connection, with at most two
live physical connections including any draining one. Reaching the stream or
connection limit returns a `limit` error.

## Failures

Use `errors.As(err, &connectError)` with `var connectError *tiana.Error`.
`Kind` separates configuration, TCP, TLS, HTTP/2, response validation, Gateway
refusal, timeout, cancellation, closure and capacity errors. `Status`, `Code`
and `RetryAfter` contain bounded Gateway metadata; peer bodies, unknown codes
and GOAWAY debug text are discarded. `RequestID` identifies stream failures.
`403/QUOTA_EXCEEDED` is preserved as a non-retryable refusal. The optional
quota reason in the JSON body is not exposed; use Gateway observability to
distinguish compute/storage exhaustion.

`Committed` records an observed complete 200 response, including a malformed
success envelope. A subsequent failure has an unknown inner session outcome.
The CONNECT client never reconnects or replays an operation automatically. `Unprocessed`
is separate from `Retryable()`: retryability requires a 1–60,000 ms hint and
one of `429/CONNECTION_LIMIT`, `503/POLICY_UNAVAILABLE`,
`503/INSTANCE_UNAVAILABLE` or `504/ACTIVATION_TIMEOUT`, before commit.

## Runnable example and verification

`examples/echo` relays stdin to an echo upstream and received bytes to stdout.
It reads an optional token from `TIANA_TOKEN` and custom trust from
`TIANA_CA_FILE`. Example usage with an isolated fixture:

```sh
TIANA_ENDPOINT=ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test \
TIANA_GATEWAY_ADDRESS=127.0.0.1:12345 \
TIANA_CA_FILE=/path/to/fixture/fixtures/gateway.pem \
go run ./examples/echo < payload.bin
```

Run the self-contained checks with no private services:

```sh
go test -race ./...
go vet ./...
python3 scripts/check-public-source.py
bash scripts/consumer-smoke.sh
```

The smoke script exports the **current source**, including uncommitted changes,
builds the echo example in a separate consumer module, then verifies exact
bytes and half-close against a local synthetic TLS/H2 peer. Go, Python 3,
Bash, and access to public Go dependencies are required. Temporary smoke
artifacts are cleaned on exit.

`conformance/v1` is a self-contained public CONNECT test distribution with
its own identity and hashes. It is adapted for explicit deployment hostnames;
it does not claim byte identity with older distributions. TLS fixtures are
synthetic and regenerable, with reserved `.test` names.

See [validation instructions](docs/validation.md) for reproducible tests
against the pinned Gateway source and how to export a source snapshot without Git history.

## Migration and limitations

This pre-release migration changes the module import path and requires a
complete Endpoint hostname. The previous exported default suffix constant
has been removed. Change imports and pass the deployment hostname explicitly;
TLS trust configuration and physical DialAddress overrides still work.

Unit tests and consumer smoke use local synthetic peers. They do not prove
interoperability with a deployed Gateway/Agent/database combination or database
transaction behavior. External integration is a separate opt-in step. GitHub
CI and no-replace public installation can only be verified once this candidate
has been published to a review branch or release respectively.

Go-managed credential strings and library buffers cannot be guaranteed to be
zeroized; callers control the original token input's storage and lifetime.

### Web resource and publication transports

`fetch.NewResourceClient` sends GET/HEAD as native HTTP/1.1 through a regular
CONNECT stream using `tiana.TianaHTTP`, selecting channel=0/data.sock. Encoded
bytes remain encoded; no automatic redirect, decompression or request replay.
`fetch.NewClient` sends HTTP control through TFQ1/TFS1 with protocol=tiana-http,
selecting channel=1/http-data.sock. There is no metadata channel selector.
Publication endpoints are under /_tiana/web/ and always require a valid Token whose
Endpoint, Instance, Group or Tenant scope covers the target. Token scope is
independent of the instance engine and channel; anonymous resources do not grant
anonymous publication. SDKs pass credentials unchanged without choosing a kind.
Both reuse Gateway–Agent v4. Consumers must pin a published module revision containing these additions.
