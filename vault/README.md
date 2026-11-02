# Vault client

`NewClient` uses an existing `fetch.Client` for the Gateway `tiana-http` channel.
Configure its endpoint and token before calling `Get`, `Set`, `Remove` or `List`.
Internal platform callers supply the Gateway internal `DialAddress`.

`Get` additionally needs the base64 safety passphrase and instance ID. The client
signs the decoded key and Unix timestamp immediately before the request; the
server accepts a time difference of at most 15 seconds. Errors and expired
signatures are returned without replaying the operation.

`Set` preserves whitespace and empty values. A changed value increments the
current version; an identical value keeps it. Only the current value is stored.
`List` returns key/version metadata and a cursor, with optional literal substring
search. `Remove` deletes the key. `ErrNotExist` distinguishes an absent key;
`ErrResultUnknown` means the caller must independently check the result before
choosing whether to issue another write.

The CLI uses MGR's Init/List/Set/Remove routes. It does not expose this client's
Get method or a plaintext export command.
