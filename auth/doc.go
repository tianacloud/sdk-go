// Package auth provides the CLI-compatible MGR account authentication and local
// credential stores. It is separate from the root package's CONNECT transport:
// MGR account access/refresh tokens must never be used as InstanceTokens.
//
// New requires an explicit MGR origin. DefaultOrigin reads TIANA_API_ORIGIN
// and returns empty when it is unset or blank. There is no
// compiled deployment address. By default, account and InstanceToken files use
// $XDG_CONFIG_HOME/tiana, or ~/.config/tiana when XDG_CONFIG_HOME is unset.
// Store paths and JSON formats match the existing CLI; no migration is needed.
// Callers may supply a CredentialStore to avoid filesystem-backed accounts.
//
// Login performs the existing browser-mediated cli_login transaction. Output is
// silent unless Config.Output is supplied. CreateAuthTransaction and
// PollAuthTransaction permit inspection of transactions; Login owns the full
// authorization-code exchange flow. RunAuthenticated may log in unless NonInteractive is set;
// EnsureCredential and DoJSON only load/refresh existing credentials.
//
// InstanceToken selection must follow successful MGR authorization of the target
// for the active account. Local credentials are capabilities, not authorization
// proof. Candidate selection preserves origin/tenant scoping, expiry skew and
// newest-record selection, and never falls back outside IDs returned by MGR.
// It neither creates tokens nor retries a rejected Gateway connection.
//
// File stores on Linux/macOS require owned mode-0600 regular files and private
// mode-0700 directories. Windows uses current-user ownership and owner-only
// ACLs, checks opened disk-file handles and rejects final reparse points. Reads
// on all three platforms reject non-regular input and cap JSON at 8 MiB. Other
// platforms fail closed; callers may supply a custom CredentialStore.
// Writes create a private same-directory temporary file, sync and rename it.
// Readers see a complete old or new file.
// Persistent adjacent .lock files serialize read-modify-write operations across
// cooperating clients/processes. Refresh holds the account-file lock across
// reload, server token rotation and persistence; logout uses the same lock.
// Lock waits honor context cancellation and have a 30-second maximum. Never
// delete lock files while clients may run. Different origins sharing one file
// wait on the same lock. Use local filesystems supporting flock on Linux/macOS
// or ACLs and LockFileEx on Windows.
// Custom stores still require external synchronization across clients/processes.
// Older SDK/CLI binaries do not participate in these locks and must not mutate
// the same stores concurrently. No directory fsync or power-loss guarantee is
// added; a crash after server rotation but before local Save may require login.
//
// MGR URLs require HTTPS except literal loopback IPs and localhost for local
// development. Diagnostics omit arbitrary peer messages, transport parser text
// and unrecognized codes. APIError retains structured recovery metadata; do not
// log it through JSON or print unwrapped transport causes without sanitization.
package auth
