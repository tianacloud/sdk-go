// The instance token grants Function access; the application session identifies
// the end user. Neither credential is placed in page data or URLs.
function createAppAuth(wx, config) {
  let session = null
  let generation = 0

  function request(path, method, data, token) {
    if (!config.origin || !config.instanceToken) {
      return Promise.reject(new Error('请先配置演示函数地址与实例 Token'))
    }
    const header = {
      Authorization: `Bearer ${config.instanceToken}`,
      'content-type': 'application/json',
    }
    if (token) header['X-App-Session'] = token
    return new Promise((resolve, reject) => {
      wx.request({
        url: config.origin + path, method, data, header, timeout: 15000,
        success(res) {
          if (res.statusCode >= 200 && res.statusCode < 300) return resolve(res.data)
          const code = res.data && res.data.error
          const error = new Error(code || `请求失败（${res.statusCode}）`)
          error.status = res.statusCode
          error.code = code
          error.providerCode = res.data && res.data.provider_code
          reject(error)
        },
        fail() { reject(new Error('网络请求失败，请检查小程序合法域名与网络')) },
      })
    })
  }

  function current() {
    if (!session || session.expires_at * 1000 <= Date.now()) {
      session = null
      throw new Error('请先微信登录')
    }
    return session
  }

  return {
    async login() {
      const attempt = ++generation
      const code = await new Promise((resolve, reject) => {
        wx.login({
          success(result) {
            if (result.code) resolve(result.code)
            else reject(new Error('微信未返回登录凭证，请重试'))
          },
          fail() { reject(new Error('微信登录失败，请重试')) },
        })
      })
      if (attempt !== generation) throw new Error('登录操作已结束')
      const result = await request('/auth/login', 'POST', { code })
      if (attempt !== generation) throw new Error('登录操作已结束')
      if (!result || !result.token || !result.identity || !result.identity.open_id ||
          !(result.expires_at * 1000 > Date.now())) throw new Error('登录响应不完整')
      session = result
      return { identity: result.identity, expiresAt: result.expires_at }
    },
    async me() {
      return request('/me', 'GET', undefined, current().token)
    },
    async greet(message) {
      return request('/greet', 'POST', { message }, current().token)
    },
    async verifyIdentity() {
      const active = current()
      const results = []
      for (const [name, token] of [
        ['只有实例 Token，未带用户会话', ''],
        ['用户会话被篡改', alterSignature(active.token)],
      ]) {
        try {
          await request('/me', 'GET', undefined, token)
          results.push({ name, passed: false, detail: '请求被错误接受' })
        } catch (error) {
          results.push({ name, passed: error.status === 401 && error.code === 'APP_SESSION_REQUIRED',
            detail: error.status === 401 && error.code === 'APP_SESSION_REQUIRED' ? '函数拒绝请求（401）' : error.message })
        }
      }
      const response = await request('/greet', 'POST', { message: '身份校验', user_id: 'another-user', open_id: 'another-user' }, active.token)
      const passed = response.identity.app_id === active.identity.app_id && response.identity.open_id === active.identity.open_id
      results.push({ name: '请求正文自报另一个用户', passed,
        detail: passed ? '函数仍使用会话验证出的真实身份' : '返回身份不匹配' })
      return results
    },
    clear() { generation++; session = null },
  }
}

function alterSignature(token) {
  const index = token.indexOf('.') + 1
  return token.slice(0, index) + (token[index] === 'A' ? 'B' : 'A') + token.slice(index + 1)
}

module.exports = { createAppAuth }
