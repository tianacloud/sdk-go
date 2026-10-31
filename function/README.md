# Function helpers

Import `github.com/tianacloud/sdk-go/function` inside a Tiana Go Function:

```go
parameters, err := function.ReadConfig()
if err != nil {
    return err
}
endpoint, ok := parameters.Get("SQLITE_ENDPOINT")
if !ok {
    return errors.New("SQLITE_ENDPOINT is not configured")
}
token, ok := parameters.Get("SQLITE_TOKEN")
if !ok {
    return errors.New("SQLITE_TOKEN is not configured")
}
```

The platform supplies `FUNCTION_CONFIG_FILE`, pointing to the function's read-only
JSON parameter file. Each call reads the file, so a later call can observe saved
parameter changes without restarting the function. During an incomplete update,
the last successfully decoded configuration is returned; a failed initial read
returns an error. Each returned Config is independent. Get returns the value and its presence; an
existing empty value returns true, while a missing key returns false. This helper reads parameters;
changes are made in Console.

Inside an HTTP handler, read the authenticated caller for that request:

```go
caller, present := function.CallerFromRequest(r)
if present {
    userID := caller.UserID
    selectedTenantID := caller.TenantID
    // Use these values in this request's business logic.
    _, _ = userID, selectedTenantID
}
```

The tenant is the caller's selected tenant; it is not necessarily the function
owner's tenant. A machine Token has no logged-in caller. An incomplete, duplicate
or malformed pair also returns `present=false`. The helper reads only this
request and keeps no global user state. It consumes the managed Gateway's
authorization result; it is not an authentication method for an independently
exposed HTTP server.

For calls originating from a Web App, `caller.AppOwnerID` identifies that Web's
creator. Use `caller.IsAppOwner()` for author-only initialization or permission
management. It compares the current user with the source Web creator and returns
false without a Web context. Different Web Apps may use the same Function with
different creators. Tenant roles and the Function or Token creator are separate
from this request-level identity.

`caller-context.json` is the local copy of the minimal shared HTTP name
declaration. Consumer tests check the implementation against it; cross-component
acceptance checks its bytes against the contracts artifact and reads actual
Gateway/App request bytes with this public SDK. The declaration has no runtime
network or private module dependency.
Full environment acceptance is tracked separately from package tests. The shared
declaration source is recorded below.

## Shared declaration provenance

The exact local `caller-context.json` declaration comes from contracts
`v0.82.0-function.4`, commit `eb0373d0c845fd6dff7ed59a5ea0723ffe6ba3b4`.
Its SHA-256 is `9afd1c6e668ef8c506389d1fd1f486f90240f8e818b3342f9c4e2a41d55206e3`.
This identifies the shared header names; it does not replace the provenance of
other protocols or imply full environment acceptance.

## Asynchronous jobs

Call `job, err := function.StartJob(jobID)` before starting a background goroutine.
After successful registration, call `job.Finish()` when work ends and handle its error.
A registered job blocks automatic idle sleep. Starting an active ID is idempotent;
finishing an absent or finished ID succeeds. Starting that ID after Finish registers
a new job. Finish can be retried. Registrations are local to one execution and reset
on restart. Force sleep, resource limits and failures may still interrupt work;
store recoverable progress externally.

## Parameter files

Local files use `{"MESSAGE":{"kind":"plain","value":"Hello"}}`; set
`FUNCTION_CONFIG_FILE` to the path. Plain entries do not require a secret key.
The platform may supply `encoded` entries and `FUNCTION_CONFIG_SECRET_KEY`.
The SDK authenticates and decrypts these entries before returning plaintext Config.
An invalid key, ciphertext or entry kind returns an error even if an earlier read
succeeded. Only a fully decoded configuration replaces the cached result.
