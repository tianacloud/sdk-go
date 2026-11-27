# WeChat mini-program application authentication

`github.com/tianacloud/sdk-go/wechatmini` verifies `wx.login()` codes with WeChat,
issues signed application sessions, and makes the verified identity available in
an HTTP request context. The identity is the pair `(AppID, OpenID)`; the
application owns any mapping to its business users and their data permissions.

```go
authenticator, err := wechatmini.New(wechatmini.Config{
    AppID: appID,
    AppSecret: appSecret,
    SigningKey: signingKey,
    SessionTTL: time.Hour,
})
if err != nil {
    return err
}

// code comes from the mini program's wx.login callback.
session, err := authenticator.Login(ctx, code)
if err != nil {
    return err
}
// Return session as JSON from the application's login endpoint.
```

The backend supplies the WeChat AppSecret and an independently generated signing
key of at least 32 random bytes. Store these as Function secret parameters and
reuse the same key across executions. `New` performs no network or filesystem
operations. A custom HTTP client may supply an outbound transport; the library
copies it, bounds the exchange to ten seconds, and does not follow redirects.
Login returns only the application session, identity and Unix-second expiration.
Provider `session_key` and AppSecret are not returned. Numeric WeChat failures
are available by using `errors.As` with a `*wechatmini.ProviderError` target; upstream text and
credential-bearing transport errors are not exposed.

Protect each business route and use its verified context:

```go
mux.Handle("GET /me", authenticator.Middleware(http.HandlerFunc(
    func(w http.ResponseWriter, r *http.Request) {
        identity, _ := wechatmini.FromContext(r.Context())
        json.NewEncoder(w).Encode(identity)
    },
)))
```

Requests carry the Function instance credential in `Authorization: Bearer <token>`
and the application session in `X-App-Session`.

Gateway validates the instance credential. `Middleware` verifies the application
session's HMAC-SHA256 signature, AppID and expiration locally, then attaches that
identity to this request. A missing, invalid or expired session returns HTTP 401
with `APP_SESSION_REQUIRED`. A client-supplied user ID is not the identity source.
Function `CallerFromRequest` continues to represent the separate platform caller.

Sessions have a fixed lifetime and verification does not extend it. After expiry,
perform `wx.login()` again. Client logout clears the local session; a copied
credential remains valid until its signed expiration. Changing the signing key
invalidates sessions issued with the old key when executions load the new key.
The application remains responsible for business authorization, such as selecting
orders by its verified user rather than accepting an arbitrary owner ID.
