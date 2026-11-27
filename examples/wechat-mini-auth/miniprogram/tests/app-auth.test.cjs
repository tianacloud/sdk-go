const test = require('node:test')
const assert = require('node:assert/strict')
const { createAppAuth } = require('../services/app-auth')

function fixture() {
  const requests = []
  const identity = { app_id: 'wx-demo', open_id: 'verified-alice' }
  const wx = {
    login({ success }) { success({ code: 'fresh-wechat-code' }) },
    request(options) {
      requests.push(options)
      if (options.url.endsWith('/auth/login')) {
        options.success({ statusCode: 200, data: { token: 'payload.signature', identity, expires_at: Math.floor(Date.now() / 1000) + 3600 } })
      } else if (options.header['X-App-Session'] !== 'payload.signature') {
        options.success({ statusCode: 401, data: { error: 'APP_SESSION_REQUIRED' } })
      } else options.success({ statusCode: 200, data: { identity, message: options.data && options.data.message } })
    },
  }
  return { wx, requests, identity, auth: createAppAuth(wx, { origin: 'https://function.example.test', instanceToken: 'shared-instance-credential' }) }
}

test('wx.login code is exchanged and application session accompanies business calls', async () => {
  const f = fixture()
  const login = await f.auth.login()
  assert.deepEqual(login.identity, f.identity)
  assert.equal(login.token, undefined)
  assert.deepEqual(f.requests[0].data, { code: 'fresh-wechat-code' })
  assert.equal(f.requests[0].header['X-App-Session'], undefined)
  const response = await f.auth.greet('hello')
  assert.deepEqual(response.identity, f.identity)
  assert.equal(f.requests[1].header['X-App-Session'], 'payload.signature')
  assert.equal(f.requests[1].header.Authorization, f.requests[0].header.Authorization)
})

test('identity checks distinguish rejected sessions from provider failures', async () => {
  const f = fixture()
  await f.auth.login()
  const checks = await f.auth.verifyIdentity()
  assert.equal(checks.length, 3)
  assert.ok(checks.every(check => check.passed))
  assert.equal(f.requests.at(-1).data.user_id, 'another-user')
  f.wx.request = options => options.success({ statusCode: 401, data: { error: 'INVALID_INSTANCE_TOKEN' } })
  await assert.rejects(f.auth.verifyIdentity(), { code: 'INVALID_INSTANCE_TOKEN' })
})

test('clearing local session prevents later authenticated calls', async () => {
  const f = fixture()
  await f.auth.login()
  f.auth.clear()
  await assert.rejects(f.auth.me(), /请先微信登录/)
})

test('late login does not restore a cleared session', async () => {
  const f = fixture()
  let complete
  f.wx.request = options => { complete = options.success }
  const pending = f.auth.login()
  await Promise.resolve()
  f.auth.clear()
  complete({ statusCode: 200, data: { token: 'payload.signature', identity: f.identity, expires_at: Math.floor(Date.now() / 1000) + 3600 } })
  await assert.rejects(pending, /登录操作已结束/)
  await assert.rejects(f.auth.me(), /请先微信登录/)
})
