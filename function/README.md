# Function helpers

Import `github.com/tianacloud/sdk-go/function` inside a Tiana Go Function:

```go
parameters, err := function.ReadConfig()
if err != nil {
    return err
}
endpoint, err := parameters.Get("SQLITE_ENDPOINT")
if err != nil {
    return err
}
token, err := parameters.Get("SQLITE_TOKEN")
if err != nil {
    return err
}
```

The platform supplies `FUNCTION_CONFIG_FILE`, pointing to the function's read-only
JSON parameter file. Plain values can be updated in place. Changes to secret
references take effect at the next cold start. During an incomplete file update,
the last successfully decoded configuration is returned; a failed initial read
returns an error. Each returned Config owns its typed definitions.

Get returns `(value, error)`. `errors.Is(err, function.ErrNotExist)` identifies a
missing parameter or target secret. An existing empty value returns `("", nil)`.
Plain values are local; secret references are resolved by the execution supervisor,
which accepts only parameter names declared as secret in this execution. The
first successful value is cached for that execution. ReadConfig itself does not
fetch secrets. Changes are made in Console.

Use `GetContext` inside an HTTP handler to carry its cancellation and diagnostic
identity to the supervisor:

```go
ctx := function.ContextFromRequest(r)
token, err := parameters.GetContext(ctx, "SQLITE_TOKEN")
if err != nil {
    var requestErr *function.RequestError
    if errors.As(err, &requestErr) {
        log.Printf("secret request failed: request_id=%s status=%d", requestErr.RequestID, requestErr.Status)
    }
    return
}
_ = token
```

`ContextFromRequest` copies `x-request-id` and `traceparent` from that request;
use a separate derived context for each concurrent incoming request. `GetContext`
also accepts an ordinary `context.Context`. Without an inherited request ID, it
generates an independent ID before sending the secret request. `Get` uses a
background context and an independent ID; it does not imply a relationship to
an HTTP handler. Plain parameters are still returned locally.

`RequestError.RequestID` identifies failures even when no response arrives;
`Status` is zero in that case. A response's `x-request-id` is retained when
present. `errors.Is` still identifies `ErrNotExist`, `context.Canceled` and
`context.DeadlineExceeded` from caller cancellation. Errors contain neither the
secret value nor the supervisor response body. The SDK does not retry the lookup.

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
`v0.96.0-rc.1`, commit `45f98221922bfb4a725e692be5caffac579a781b`.
Its SHA-256 is `79a10dfbc0a3d6bf722a5b18a57089899da5bdf6597a38b27d81b7b5ced3a86b`.
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
A secret entry is `{"PASSWORD":{"kind":"secret","value":"production/password"}}`.
Its value is a reference key, not secret plaintext. Get sends the parameter name
`PASSWORD` to the supervisor's `/get_secret` endpoint. The SDK performs no local
parameter encryption or decryption. Unsupported entry kinds return an error.
