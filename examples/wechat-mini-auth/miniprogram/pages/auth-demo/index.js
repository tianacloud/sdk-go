const { createAppAuth } = require('../../services/app-auth')
let config
try { config = require('../../auth-demo.config.local') }
catch (_) { config = {} }

Page({
  data: { busy: false, loggedIn: false, status: '尚未登录', openID: '', appID: '', expiry: '', message: '你好，Tiana Function', reply: '', checks: [] },
  onLoad() { this.auth = createAppAuth(wx, config); this.alive = true },
  onUnload() { this.alive = false; this.auth.clear() },
  updateMessage(event) { this.setData({ message: event.detail.value }) },
  async run(operation) {
    if (this.data.busy) return
    this.setData({ busy: true })
    try { await operation() }
    catch (error) {
      if (this.alive) this.setData({ status: error.message + (error.providerCode ? `（微信错误码 ${error.providerCode}）` : '') })
    } finally { if (this.alive) this.setData({ busy: false }) }
  },
  login() {
    return this.run(async () => {
      const result = await this.auth.login()
      if (this.alive) this.setData({ loggedIn: true, status: '微信身份已由函数验证',
        openID: result.identity.open_id, appID: result.identity.app_id,
        expiry: new Date(result.expiresAt * 1000).toLocaleString(), reply: '', checks: [] })
    })
  },
  callFunction() {
    return this.run(async () => {
      const result = await this.auth.greet(this.data.message)
      if (this.alive) this.setData({ status: '函数调用成功', reply: `${result.reply}\n${result.message}\n当前 OpenID：${result.identity.open_id}` })
    })
  },
  verify() {
    return this.run(async () => {
      const checks = await this.auth.verifyIdentity()
      if (this.alive) this.setData({ checks, status: checks.every(item => item.passed) ? '三项身份校验全部通过' : '身份校验未全部通过，请检查结果' })
    })
  },
  clearSession() {
    this.auth.clear()
    this.setData({ loggedIn: false, status: '本机会话已清除', openID: '', appID: '', expiry: '', reply: '', checks: [] })
  },
})
