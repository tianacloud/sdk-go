# Files inside a Function

Use `function.Files()` for the Function owner's tenant files root,
`function.FilesByWebApp(webID)` for its `<webID>/` child directory, or
`function.FilesFromRequest(r)` for the source Web identified by Gateway.
The latter two return `(*files.Client, error)`; absent request Web context returns
`files.ErrNoWebContext`. Construction performs no I/O. Runtime supplies storage
configuration through the supervisor; no OSS keys belong in the user program.

```go
client, err := function.FilesFromRequest(r)
if err != nil { return err }
ctx := function.ContextFromRequest(r)
content := []byte("report\n")
receipt, err := client.Put(ctx, "reports/latest.txt", bytes.NewReader(content), files.PutOptions{
    Size: int64(len(content)), ContentType: "text/plain; charset=utf-8",
})
if err != nil { return err }
publicURL, err := client.GetURL(ctx, receipt.Path)
```

Import `bytes`, `github.com/tianacloud/sdk-go/files` and
`github.com/tianacloud/sdk-go/function`. The snippet belongs inside a handler's
authorized business operation. Directory selection does not implement application
user permissions; use the trusted caller information for those decisions.

| Method | Result |
| --- | --- |
| `List(ctx, path, files.ListOptions{Cursor: cursor})` | `files.Page`: entries and next cursor; an empty path lists the client root |
| `Metadata(ctx, path)` | Size, ETag, content type, modification time and write ID |
| `Get(ctx, path, files.GetOptions{})` | `*http.Response`; close Body after reading |
| `GetURL(ctx, path)` | Complete public file entry URL; browser file authorization still required |
| `Put(ctx, path, reader, files.PutOptions{Size: size})` | Write receipt; exact byte length is required, including zero |
| `Delete(ctx, path)` | Delete the current key; absent objects succeed |
| `Capabilities(ctx)` | Maximum file size and most recently applied write-block state |

All input and returned paths are relative to this client's root. For example,
Web client path `reports/latest.txt` equals tenant client path
`<webID>/reports/latest.txt`. A different tenant's Web ID still selects a child
of the Function owner's root. List cursors belong to the same client and directory;
pass `NextCursor` back until it is empty.

Get supports `Method: http.MethodHead` and `Range: "bytes=0-99"`.
Cancellation follows the supplied context. Read bodies remain streamed; small
metadata operations have a 30-second deadline. Put defaults to conditional
creation. `Overwrite: true` deletes then creates and is not atomic. No file write
is automatically retried. Size may be zero through 5 GiB.

Use `errors.As(err, &fileErr)` with `var fileErr *files.Error` to inspect Code,
Stage, Outcome, DeleteConfirmed, WriteID and RequestID. An unknown outcome may
have changed the object. Inspect current Metadata and your business state before
deciding what to do; WriteID is an upload marker, not an idempotency key or proof
of historical content. If a canceled request needs a follow-up read, give that
read its own context.

Storage is accounted asynchronously. WriteBlocked is an applied snapshot, not
remaining bytes. It blocks Put, including overwrite; file reads and deletion
remain available. Each actual List adds 100 file reads. Existing tenant admission
may independently block new Function requests. Public URLs share the frontend
file entry and grants; they are neither OSS signed URLs nor credential-bearing
links.

The supervisor HTTP declaration copied to `internal/functionfiles/function-files.json`
comes from contracts `v0.96.0-rc.1`, commit
`45f98221922bfb4a725e692be5caffac579a781b`, SHA-256
`1cd5cc6a02f8aaded06e7d193beb5425f5d3a9fc2d9c6e7d746b47d37f5a17f4`.
Consumer tests verify the declared operations. The public module has no private
contracts module dependency.
