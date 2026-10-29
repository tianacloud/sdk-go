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

`caller-context.json` is the local copy of the minimal shared HTTP name
declaration. Consumer tests check the implementation against it; cross-component
acceptance checks its bytes against the contracts artifact and reads actual
Gateway/App request bytes with this public SDK. The declaration has no runtime
network or private module dependency. The Function helpers are available in the `v1.1.0-function.2` prerelease.
Full environment acceptance is tracked separately from package tests. The shared
declaration source is recorded below.

## Shared declaration provenance

The exact local `caller-context.json` declaration comes from contracts
`v0.82.0-function.1`, commit `7f7dfa4764ffa0318b264bfcd6acf3810005287e`.
Its SHA-256 is `5a9fd83ce058e75a3ccdf5377e9f6559376db7cf3a4170fbbb4c3941769968f4`.
This identifies the shared header names; it does not replace the provenance of
other protocols or imply full environment acceptance.
