# Native mini-program Function authentication demo

The demo uses one Function instance credential for every caller. WeChat verifies
the end user during login; business routes verify a separate signed application
session through `wechatmini`. Users remain application users.

## Backend

Publish `main.go` with the matching SDK source. Configure these Function parameters:

| Name | Kind | Value |
| --- | --- | --- |
| `WECHAT_APP_ID` | plain | The mini program's AppID |
| `WECHAT_APP_SECRET` | secret | A secret-store key containing its AppSecret |
| `APP_SESSION_KEY` | secret | A secret-store key containing base64-encoded 32 random bytes |

The example imports the `wechatmini` package added in this source tree. Before a
release containing it is available, a local module replacement or a source
snapshot is required; existing published SDK versions do not contain this package.
Keep the signing key stable across function executions. Parameters are read using
the Function SDK; the service listens on `PORT` (8080 for local execution).
In the Function's advanced service settings, enable the port health check. This
example resolves secret parameters before listening; the check makes the first
request wait for that initialization. Saving the setting takes effect on the
next Function startup.

| Request | Application session | Result |
| --- | --- | --- |
| `GET /health` | none | Service readiness |
| `POST /auth/login`, JSON `{ "code": "..." }` | none | Verified identity, signed session and expiration |
| `GET /me` | `X-App-Session` | Verified application identity |
| `POST /greet`, JSON `{ "message": "..." }` | `X-App-Session` | Message and the verified caller identity |

Every request through the managed Function endpoint also needs the Function
instance credential in `Authorization`. The application session lasts one hour.

## Mini program

Copy `miniprogram/services/app-auth.js` and `miniprogram/pages/auth-demo/` into an
existing mini-program project. Add `pages/auth-demo/index` to `app.json.pages`.
Use the real AppID in the project's configuration. Configure the Function origin
as a request legal domain in the WeChat console before real-device acceptance.

Create `miniprogram/auth-demo.config.local.js` with the actual Function origin and
its instance token. Keep this local configuration outside source control:

```javascript
module.exports = {
  origin: functionOrigin,
  instanceToken: functionInstanceToken,
}
```

The values above are configuration variables, not literal values to paste. The
WeChat AppSecret and session signing key belong only in the backend secret store.
The instance token included in a distributed mini program is a shared transport
credential; each protected business route uses the application-session middleware
to identify the user and perform its own business authorization.

Open the demo page and select **微信登录**, **发送并读取当前身份**, then **运行三项检查**.
The checks send the same instance token with a missing session, an altered session,
and a valid session plus a different self-reported user. The first two must return
401; the third must retain the original verified identity. Login as a second
WeChat user to confirm that the backend reports a different OpenID while the
instance credential remains unchanged.

The client keeps its user session in memory. Closing the page or choosing
**清除本机会话** clears it locally; it does not revoke an already copied session.
After expiry or re-opening the page, log in again. Login and business requests are
not automatically replayed after an uncertain response.

## Local verification

From the SDK repository root:

```sh
go test -race ./wechatmini ./examples/wechat-mini-auth
node --test examples/wechat-mini-auth/miniprogram/tests/*.cjs
go test ./wechatmini -run '^$' -bench BenchmarkVerify -benchmem
```

Tests use a synthetic WeChat provider and two distinct users. They verify request
identity, signatures, expiry, application scope, cancellation and provider errors.
Real WeChat login additionally requires a fresh code from the real mini program;
unit tests do not establish that acceptance.
