/* app.js — 应用入口：登录态管理、路由、导航 */

let ME = null;

async function loadMe() {
  try { ME = await get('/api/v1/me'); } catch (e) { ME = null; }
  return ME;
}

function applyIdentity() {
  const who = document.getElementById('whoami');
  if (ME) {
    const role = ME.user.role === 'admin' ? '平台管理员' : '租户用户';
    const tenantName = ME.tenant ? ME.tenant.name : '';
    who.innerHTML = '<b>' + esc(ME.user.username) + '</b><br>' + esc(role) + (tenantName ? ' · ' + esc(tenantName) : '');
    document.querySelectorAll('.admin-only').forEach(a => a.style.display = ME.user.role === 'admin' ? '' : 'none');
  }
}

function showLogin() {
  document.getElementById('view-login').classList.remove('hidden');
  document.getElementById('view-main').classList.add('hidden');
}

function showMain() {
  document.getElementById('view-login').classList.add('hidden');
  document.getElementById('view-main').classList.remove('hidden');
}

async function boot() {
  // 登录表单
  const savedBase = localStorage.getItem('dns_api_base');
  if (savedBase) document.getElementById('login-api').value = savedBase;

  document.getElementById('login-btn').onclick = async () => {
    const base = document.getElementById('login-api').value.trim() || (location.protocol + '//' + location.hostname + ':8001');
    setApiBase(base);
    const u = document.getElementById('login-user').value.trim();
    const p = document.getElementById('login-pass').value;
    const msg = document.getElementById('login-msg');
    msg.textContent = '';
    try {
      const r = await post('/api/v1/auth/login', { username: u, password: p });
      setTokens(r.access_token, r.refresh_token);
      msg.textContent = '登录成功，正在进入…';
      msg.style.color = 'var(--ok)';
      await enter();
    } catch (e) {
      msg.textContent = e.message;
    }
  };
  document.getElementById('login-pass').addEventListener('keydown', ev => {
    if (ev.key === 'Enter') document.getElementById('login-btn').click();
  });

  document.getElementById('logout-btn').onclick = async () => {
    try { await post('/api/v1/auth/logout', {}); } catch (e) {}
    setTokens('', '');
    location.hash = '#/login';
    showLogin();
  };

  // 导航
  document.querySelectorAll('#nav a').forEach(a => {
    a.onclick = () => { location.hash = '#/' + a.dataset.view; };
  });

  // 路由
  const route = () => {
    const h = location.hash.replace(/^#\//, '');
    const view = Views[h] ? h : 'dashboard';
    renderView(view);
  };
  window.addEventListener('hashchange', route);

  if (getToken()) {
    await enter();
  } else {
    location.hash = '#/login';
    showLogin();
  }

  async function enter() {
    const ok = await loadMe();
    if (!ok) { showLogin(); return; }
    applyIdentity();
    showMain();
    if (!location.hash || location.hash === '#/login') location.hash = '#/dashboard';
    route();
  }
}

document.addEventListener('DOMContentLoaded', boot);
