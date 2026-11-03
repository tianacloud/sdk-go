# Vault client

`NewClient` uses an existing `fetch.Client` for the Gateway `tiana-http` channel.
Configure its endpoint and token before calling `Get`, `Set`, `Remove` or `List`.
Internal platform callers supply the Gateway internal `DialAddress`.

`Get` additionally needs the 22-character unpadded Base64URL safety passphrase (16 random bytes) and instance ID. The client
signs the decoded key and Unix timestamp immediately before the request; the
server accepts a time difference of at most 15 seconds. Errors and expired
signatures are returned without replaying the operation.

`Set` preserves whitespace and empty values. A changed value increments the
current version; an identical value keeps it. Only the current value is stored.
`List` returns key/version metadata and a cursor, with optional literal substring
search. `Remove` deletes the key. `errors.Is(err, vault.ErrNotExist)` distinguishes an absent key;
`errors.Is(err, vault.ErrResultUnknown)` means the caller must independently check the result before
choosing whether to issue another write.

Use `errors.As` with `*vault.Error` to read the failing response's `RequestID`,
`Status` and `Code`. Gateway transport and frame failures retain their identity
in `*fetch.Error`. Request IDs identify evidence for the specific operation;
they do not imply that a timed-out write was rolled back.

The CLI uses MGR's Init/List/Set/Remove routes. It does not expose this client's
Get method or a plaintext export command.
