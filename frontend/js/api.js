/* api.js — 与后端 REST API 通信（前后端隔离：仅通过 HTTP API + JWT） */

const API_BASE_KEY = 'dns_api_base';
let API_BASE = localStorage.getItem(API_BASE_KEY) || (location.protocol + '//' + location.hostname + ':8001');
const TOKEN_KEY = 'dns_access_token';
const REFRESH_KEY = 'dns_refresh_token';

function setApiBase(url) {
  API_BASE = url.replace(/\/+$/, '');
  localStorage.setItem(API_BASE_KEY, API_BASE);
}
function getApiBase() { return API_BASE; }

function getToken() { return localStorage.getItem(TOKEN_KEY); }
function getRefresh() { return localStorage.getItem(REFRESH_KEY); }
function setTokens(access, refresh) {
  localStorage.setItem(TOKEN_KEY, access || '');
  localStorage.setItem(REFRESH_KEY, refresh || '');
}

let refreshing = null;

async function api(path, opts = {}) {
  opts = opts || {};
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const token = getToken();
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;

  let res = await fetch(API_BASE + path, opts);
  if (res.status === 401 && getRefresh() && !opts._retry) {
    // 尝试用 refresh token 换新 access token（单次并发去重）
    if (!refreshing) {
      refreshing = (async () => {
        try {
          const r = await fetch(API_BASE + '/api/v1/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: getRefresh() })
          });
          if (r.ok) {
            const j = await r.json();
            setTokens(j.access_token, j.refresh_token);
            return true;
          }
        } catch (e) { /* ignore */ }
        return false;
      })().finally(() => { refreshing = null; });
    }
    const ok = await refreshing;
    if (ok) return api(path, Object.assign({}, opts, { _retry: true }));
    setTokens('', '');
    location.hash = '#/login';
    throw new Error('登录已过期，请重新登录');
  }
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (body && body.error) ? body.error : ('HTTP ' + res.status);
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return body;
}

const get = (p) => api(p);
const post = (p, data) => api(p, { method: 'POST', body: JSON.stringify(data || {}) });
const put = (p, data) => api(p, { method: 'PUT', body: JSON.stringify(data || {}) });
const del = (p) => api(p, { method: 'DELETE' });
