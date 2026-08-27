/* app.js — 应用入口：登录态管理、路由、导航 */

let ME = null;

async function loadMe() {
  try { ME = await get('/api/v1/me'); } catch (e) { ME = null; }
  return ME;
}

const ROLE_LABELS = { 'admin': '平台管理员', 'sysadmin': '系统管理员', 'secadmin': '安全管理员', 'auditadmin': '审计管理员', 'tenant': '租户用户' };
// 管理角色集合(非租户)
const isAdminRole = r => r && r !== 'tenant';
// 三权分立: 各管理角色可访问的管理视图
const roleCanView = (role, view) => {
  if (!role) return false;
  if (role === 'tenant') return view === 'logs'; // 租户只能看日志
  if (role === 'auditadmin') return view === 'logs' || view === 'security'; // 审计管理员看日志+审计
  if (role === 'secadmin') return view === 'logs' || view === 'security'; // 安全管理员看日志+安全
  if (role === 'admin' || role === 'sysadmin') return true; // 平台/系统管理员全看(服务器模式)
  return false;
};

function applyIdentity() {
  const who = document.getElementById('whoami');
  if (ME) {
    const role = ROLE_LABELS[ME.user.role] || ME.user.role;
    const tenantName = ME.tenant ? ME.tenant.name : '';
    who.innerHTML = '<b>' + esc(ME.user.username) + '</b><br>' + esc(role) + (tenantName ? ' · ' + esc(tenantName) : '');
    document.querySelectorAll('.admin-only').forEach(a => {
      const view = a.getAttribute('data-view') || '';
      a.style.display = roleCanView(ME.user.role, view) ? '' : 'none';
    });
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
    const base = document.getElementById('login-api').value.trim() || 'http://127.0.0.1:8080';
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
