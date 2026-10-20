/* ============================================================
   lolsp 页面访问认证 —— 服务端版前端客户端
   登录态由后端 HttpOnly Cookie 维护，本文件不含任何凭证，
   受保护链接地址也由后端在登录后返回（/sp/ 反向代理入口）。
   ============================================================ */
(function () {
  'use strict';

  function normalizeCard(key) {
    return (key || '').replace(/\s+/g, '').toUpperCase();
  }

  function post(path, payload) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    }).then(function (res) {
      return res.json().then(function (data) {
        return { status: res.status, data: data || {} };
      });
    });
  }

  // 返回 { ok, message? }
  function loginByPassword(username, password) {
    username = (username || '').trim();
    if (!username || !password) {
      return Promise.resolve({ ok: false, message: '请输入账号和密码' });
    }
    return post('/api/login', {
      mode: 'password',
      username: username,
      password: password,
    }).then(function (r) {
      return r.data.ok ? { ok: true, data: r.data }
                       : { ok: false, message: r.data.message || '登录失败' };
    });
  }

  function loginByCard(cardKey) {
    var key = normalizeCard(cardKey);
    if (!key) return Promise.resolve({ ok: false, message: '请输入卡密' });
    return post('/api/login', { mode: 'card', card: key })
      .then(function (r) {
        return r.data.ok ? { ok: true, data: r.data }
                         : { ok: false, message: r.data.message || '验证失败' };
      });
  }

  // 当前会话；未登录返回 null
  function me() {
    return fetch('/api/me', { cache: 'no-store' })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (data) { return (data && data.ok) ? data : null; })
      .catch(function () { return null; });
  }

  function logout() {
    return post('/api/logout', {}).catch(function () {});
  }

  window.LOLSP_AUTH = {
    normalizeCard: normalizeCard,
    loginByPassword: loginByPassword,
    loginByCard: loginByCard,
    me: me,
    logout: logout,
  };
})();
