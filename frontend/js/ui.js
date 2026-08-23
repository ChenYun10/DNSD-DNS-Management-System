/* ui.js — DOM 帮助函数（全部转义输出，防 XSS） */

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function el(tag, attrs, html) {
  const n = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === 'class') n.className = attrs[k];
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), attrs[k]);
    else if (attrs[k] !== undefined && attrs[k] !== null) n.setAttribute(k, attrs[k]);
  }
  if (html !== undefined) n.innerHTML = html;
  return n;
}

function toast(msg, type) {
  const t = el('div', { class: 'toast ' + (type || '') }, esc(msg));
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}
const toastOk = (m) => toast(m, 'ok');
const toastErr = (m) => toast(m, 'err');

function badgeOk(text) { return '<span class="badge badge-ok">' + esc(text) + '</span>'; }
function badgeErr(text) { return '<span class="badge badge-err">' + esc(text) + '</span>'; }
function badgeWarn(text) { return '<span class="badge badge-warn">' + esc(text) + '</span>'; }
function badgeInfo(text) { return '<span class="badge badge-info">' + esc(text) + '</span>'; }
function badgeMuted(text) { return '<span class="badge badge-muted">' + esc(text) + '</span>'; }
function badgeVip(text) { return '<span class="badge badge-vip">' + esc(text) + '</span>'; }

function boolBadge(v, yesText, noText) {
  return v ? badgeOk(yesText || '启用') : badgeMuted(noText || '停用');
}

function table(cols, rows, emptyText) {
  if (!rows || !rows.length) return '<div class="empty">' + esc(emptyText || '暂无数据') + '</div>';
  const head = '<tr>' + cols.map(c => '<th>' + esc(c.t) + '</th>').join('') + '</tr>';
  const body = rows.map(r =>
    '<tr>' + cols.map(c => '<td>' + (c.f ? c.f(r) : esc(r[c.k])) + '</td>').join('') + '</tr>'
  ).join('');
  return '<div class="tbl-wrap"><table>' + head + body + '</table></div>';
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(
    () => toastOk('已复制到剪贴板'),
    () => toastErr('复制失败')
  );
}

function copyBtn(text, label) {
  const b = el('button', { class: 'btn btn-sm btn-ghost' }, esc(label || '复制'));
  b.onclick = () => copyText(text);
  return b;
}

function fmtTime(s) {
  if (!s) return '-';
  // 后端 ts 是 UTC 字符串(如 "2026-08-23 04:16:06.123"),无时区后缀。
  // 直接 new Date() 会按本地时区解析,显示偏 8 小时 → 补 Z 按 UTC 解析再转本地。
  let iso = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(iso)) iso = iso.replace(' ', 'T') + 'Z';
  const d = new Date(iso);
  return isNaN(d) ? esc(s) : d.toLocaleString('zh-CN', { hour12: false });
}

function fmtNum(n) {
  if (n === null || n === undefined) return '-';
  return Number(n).toLocaleString('zh-CN');
}

function loadJSON(url, cb) {
  fetch(url).then(r => r.json()).then(cb).catch(() => {});
}

/* ---------- 模态框（用于表单编辑） ---------- */
function modal(title, fields, values, onSubmit) {
  const overlay = el('div', { class: 'modal-overlay' });
  const box = el('div', { class: 'modal' });
  box.appendChild(el('div', { class: 'modal-title' }, esc(title)));
  const inputs = {};
  const hints = {};
  fields.forEach(f => {
    const g = el('div', { class: 'form-group' });
    g.appendChild(el('label', {}, esc(f.label)));
    const val = values ? values[f.key] : (f.def !== undefined ? f.def : '');
    if (f.type === 'select') {
      const s = el('select', {});
      f.options.forEach(o => {
        const opt = el('option', { value: o[0] }, esc(o[1]));
        if (String(val) === String(o[0])) opt.selected = true;
        s.appendChild(opt);
      });
      inputs[f.key] = s;
      g.appendChild(s);
    } else if (f.type === 'checkbox') {
      const lab = el('label', { class: 'switch' });
      const c = el('input', { type: 'checkbox' });
      c.checked = !!val;
      inputs[f.key] = c;
      lab.appendChild(c); lab.appendChild(el('span', {}, esc(f.label)));
      g.innerHTML = ''; g.appendChild(lab);
    } else {
      const inp = el('input', { type: f.type || 'text', placeholder: f.placeholder || '' });
      if (val !== undefined && val !== null) inp.value = val;
      inputs[f.key] = inp;
      g.appendChild(inp);
    }
    // 字段级实时校验
    if (f.validate) {
      const hint = el('div', { class: 'field-hint' });
      hints[f.key] = hint;
      g.appendChild(hint);
      const check = () => {
        const err = f.validate(inputs[f.key].value);
        hint.textContent = err || '✓ 格式正确';
        hint.className = 'field-hint ' + (err ? 'hint-err' : 'hint-ok');
      };
      inputs[f.key].addEventListener('input', check);
      check();
    }
    box.appendChild(g);
  });
  const btns = el('div', { class: 'row', style: 'justify-content:flex-end;margin-top:18px' });
  const cancel = el('button', { class: 'btn btn-ghost' }, '取消');
  cancel.onclick = () => overlay.remove();
  const ok = el('button', { class: 'btn btn-primary' }, '保存');
  ok.onclick = async () => {
    const out = {};
    for (const k in inputs) {
      const inp = inputs[k];
      out[k] = inp.type === 'checkbox' ? inp.checked : inp.value;
    }
    // 校验所有字段，任一不合法则阻止提交
    for (const f of fields) {
      if (f.validate) {
        const err = f.validate(out[f.key]);
        if (err) { toastErr('「' + f.label + '」' + err); return; }
      }
    }
    try { await onSubmit(out); overlay.remove(); } catch (e) { toastErr(e.message); }
  };
  btns.appendChild(cancel); btns.appendChild(ok);
  box.appendChild(btns);
  overlay.appendChild(box);
  document.body.appendChild(overlay);
  overlay.addEventListener('click', ev => { if (ev.target === overlay) overlay.remove(); });
}

/* ---------- DoT 前缀校验（与后端 store.ValidPrefix 规则一致） ---------- */
const PREFIX_RE = /^[a-z0-9][a-z0-9-]{2,31}$/;
const RESERVED_PREFIXES = ['www', 'api', 'admin', 'dns', 'ns1', 'ns2', 'mail', 'static', 'cdn', 'vip'];
function validatePrefix(p) {
  if (!p) return '不能为空';
  if (p.length < 3) return '至少 3 位';
  if (p.length > 32) return '最多 32 位';
  if (!/^[a-z0-9]/.test(p)) return '必须以小写字母或数字开头';
  if (!/^[a-z0-9-]+$/.test(p)) return '只能包含小写字母 a-z、数字 0-9、连字符 -';
  if (RESERVED_PREFIXES.includes(p)) return '「' + p + '」是保留词，不可使用';
  return '';
}
function normalizePrefix(v) {
  // 自动转小写、去除空格（连字符保留）
  return String(v).toLowerCase().replace(/[\s_]+/g, '-').replace(/[^a-z0-9-]/g, '');
}
