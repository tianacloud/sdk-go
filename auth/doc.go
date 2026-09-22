// Package auth provides the CLI-compatible MGR account authentication and local
// credential stores. It is separate from the root package's CONNECT transport:
// MGR account access/refresh tokens must never be used as InstanceTokens.
//
// New requires an explicit MGR origin. DefaultOrigin resolves TIANA_MGR_ORIGIN,
// then TIANA_AUTH_ORIGIN, and returns empty when neither is set. There is no
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
// File writes use a same-directory mode-0600 temporary file, file sync and rename
// under a mode-0700 directory. Readers see a complete old or new file. Existing
// stores do not lock the read-modify-write transaction or sync the directory;
// callers must serialize credential mutations and refreshes, including across
// clients/processes. Concurrent writers can lose updates and power-loss durability
// is not guaranteed. Custom stores can provide stronger transactional semantics.
// The package does not change the CLI's existing persistence guarantees.
package auth
