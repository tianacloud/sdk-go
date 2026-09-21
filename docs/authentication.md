# Shared account authentication and local credentials

Import `github.com/tianacloud/sdk-go/auth` for MGR account authentication and
CLI-compatible local stores. The root `tiana` package remains the explicit
CONNECT transport. Account access/refresh credentials never authenticate a
Gateway tunnel; only an InstanceToken does that.

## Account session

```go
client, err := auth.NewWithConfig(auth.Config{
    Origin: auth.DefaultOrigin(), // Or an explicit deployment MGR origin.
    Output: os.Stderr,            // Show the browser URL when Login is invoked.
})
if err != nil { return err }
credential, err := client.EnsureCredential(ctx) // Load or refresh; never login.
if errors.Is(err, auth.ErrAuthenticationRequired) {
    credential, err = client.Login(ctx)
}
```

`DefaultOrigin` checks `TIANA_MGR_ORIGIN`, then `TIANA_AUTH_ORIGIN`, then
returns empty. No deployment address is compiled into the SDK. Empty Origin
is rejected; the CLI retains its deployment-specific default separately.
The origin may contain a reverse-proxy base path, which is preserved.
Constructors resolve paths but do not create/read credential files or perform
network requests. Supply `Config.Store` to use an application-owned store.

`Login` handles transaction creation, browser approval polling, authorization
code exchange and persistence. `RunAuthenticated` obtains a credential and
calls an operation once, initiating Login when needed unless NonInteractive
is true. Output defaults to `io.Discard`; applications using Login must supply
an output writer to present the browser URL. Low-level transaction inspection
methods do not expose a complete independent exchange flow; use Login for
end-to-end authentication. No GUI or callback listener is required.

`Whoami`, `Refresh` and `Logout` reuse the same store. Logout deletes only the
current origin's account credential, retaining other origins and InstanceTokens.
It attempts local deletion even if remote logout fails, returning that failure.
Invalid refresh grants remove the account credential and require authentication.

`DoJSON` is the authenticated MGR request boundary used by CLI resource APIs.
It refreshes and repeats once on HTTP 401, with the same payload/headers;
mutations must supply a stable Idempotency-Key. Other failures and unknown
outcomes are returned without replay. `RunAuthenticated` does not retry the
operation itself. Callers supply a deadline/cancelable context for network work.
MGR requests never follow HTTP redirects, including same-origin redirects. A
3xx response is returned as an APIError with its original status; configure the
final MGR address directly. The SDK copies a supplied HTTPClient and overrides
CheckRedirect without changing the caller's client. This also prevents refresh
JSON bodies from being replayed to another origin or a plaintext destination.
Custom RoundTrippers remain trusted application code and must not independently
redirect or forward credentials.

Default TLS verification is enabled; optional RootCAs/custom HTTPClient are
scoped to this client. InsecureTLS is an explicit MGR-only compatibility option;
it has no effect on CONNECT TLS verification.

## Existing local files

Default paths are `$XDG_CONFIG_HOME/tiana/credentials.json` and
`$XDG_CONFIG_HOME/tiana/instance-tokens.json`, or `~/.config/tiana/...` when
XDG_CONFIG_HOME is unset. This deliberately preserves the CLI's path across
platforms, rather than substituting an OS-specific configuration directory.
JSON keys, field names, timestamps and Unix-second token expiry (`-1` means
unlimited) remain unchanged. Existing users need no login or file migration.

Account records remain keyed by MGR origin; InstanceTokens remain keyed by
origin, tenant, instance and token ID. Origin key normalization removes only
surrounding whitespace and trailing slashes, preserving legacy lookup behavior.

After resolving an instance through the current authenticated MGR account:

```go
store, err := auth.NewInstanceTokenStore(client.Origin())
if err != nil { return err }
record, err := store.Lookup(instanceID, endpointID, time.Now())
if err != nil { return err }
token, err := tiana.NewToken(record.Token)
if err != nil { return err }
// Use token with an explicit complete Endpoint hostname in tiana.Config.
```

Lookup requires matching origin/instance/endpoint and unambiguous tenant
metadata. It excludes credentials with 30 seconds or less remaining and selects
the newest saved_at, using token ID to break ties. It reads at most 8 MiB from
one owned mode-0600 regular file without following its final symlink or blocking
on a FIFO. This secure lookup currently supports Linux and macOS; other
platforms fail closed. It does not mutate files, inspect remote token lists,
create credentials or try another token after a Gateway refusal.

The CLI continues to give an explicitly set TIANA_TOKEN priority (empty or
invalid values fail without fallback), and to authorize the instance through
MGR before saved-token lookup. Applications using stores directly must preserve
that authorization boundary: a local record is not proof of current account
access. Gateway enforces revocation. Formatting credential-bearing SDK values
redacts secrets, while JSON serialization intentionally retains the compatible
storage representation. Avoid logging serialized credentials.

## Persistence and concurrency boundaries

File stores retain the CLI's same-directory temporary write, file fsync and
atomic rename, with mode 0600 files and mode 0700 directories. The containing
directory is chmod'ed to 0700 even if it already exists: custom file paths must
use a dedicated private directory. Pending command recovery remains a CLI
concern and its separate path/format are not changed.

This extraction does not introduce a store lock or a cross-process refresh
coordinator. Serialize mutations/refreshes across clients and processes sharing
a store. Concurrent read-modify-write operations can overwrite updates; rotated
refresh credentials must not be raced. The parent directory is not fsync'ed,
so full power-loss durability is not promised. Readers during rename see a
complete old/new file. A custom CredentialStore may provide stronger persistence;
applications own that store's lifecycle. Go-managed strings are not guaranteed
to be zeroized.
