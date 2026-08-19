/* views.js — 各功能页面（中文界面） */

const Views = {};

/* ============================ 总览 ============================ */
Views.dashboard = {
  title: '总览',
  async render(host) {
    const [stats, info, me] = await Promise.all([
      get('/api/v1/stats/overview').catch(() => null),
      get('/api/v1/system/info').catch(() => null),
      get('/api/v1/me').catch(() => null)
    ]);
    const qps = stats ? stats.qps : 0;
    const hit = stats ? (stats.hit_rate_total_pct ?? stats.hit_rate_pct) : 0;
    const errR = stats ? (stats.error_rate_total_pct ?? stats.error_rate_pct) : 0;
    const tq = stats ? stats.total_queries : 0;
    const vip = me && me.tenant && me.tenant.vip;

    host.appendChild(el('div', { class: 'section-title' }, '系统总览'));
    host.appendChild(el('div', { class: 'section-sub' }, '实时指标 · 缓存命中率 · 全链路状态'));

    const grid = el('div', { class: 'grid grid-4' });
    grid.appendChild(statCard('QPS（60s 均值）', fmtNum(qps), '每秒查询数'));
    grid.appendChild(statCard('缓存命中率', (hit || 0).toFixed(1) + '%', '缓存层命中占比'));
    grid.appendChild(statCard('错误率', (errR || 0).toFixed(2) + '%', 'SERVFAIL / 限流'));
    grid.appendChild(statCard('累计查询', fmtNum(tq), '自实例启动以来'));
    host.appendChild(grid);

    if (vip) {
      host.appendChild(el('div', { class: 'card vip-note' },
        '<h3>👑 高价值专用通道已启用</h3><div class="help">您的租户启用了 <b>VIP 专用通道</b>：专属上游组、' +
        '独立缓存命名空间、' + (stats ? '' : '') + '更高限流配额（10×），并可通过管理端 mTLS 管理通道进行配置。</div>'));
    }

    const infoCard = el('div', { class: 'card' });
    infoCard.appendChild(el('h3', {}, '平台信息'));
    const rows = [
      ['实例 ID', stats ? stats.instance_id : '-'],
      ['基础域名 (Base Domain)', info ? info.base_domain : '-'],
      ['DNSSEC 模式', info ? info.dnssec_mode : '-'],
      ['ECS 传递', info && info.ecs_enabled ? '已启用' : '停用'],
      ['功能矩阵', info && info.features ? info.features.join(' / ') : '-']
    ];
    // 简单信息行（table 返回 HTML 字符串，不能 appendChild）
    infoCard.innerHTML = '<h3>平台信息</h3>' + rows.map(r =>
      '<div class="row" style="justify-content:space-between;border-bottom:1px solid rgba(38,51,79,.4);padding:8px 0;margin:0">' +
      '<span class="tag">' + esc(r[0]) + '</span><span class="mono">' + esc(r[1]) + '</span></div>'
    ).join('');
    host.appendChild(infoCard);
  }
};

function statCard(label, value, sub) {
  const d = el('div', { class: 'stat' });
  d.appendChild(el('div', { class: 'v' }, esc(value)));
  d.appendChild(el('div', { class: 'l' }, esc(label)));
  d.appendChild(el('div', { class: 's' }, esc(sub)));
  return d;
}

/* ============================ DoT / DoH 端点 ============================ */
Views.dot = {
  title: 'DoT / DoH 端点定制',
  async render(host) {
    const me = await get('/api/v1/me');
    const tenant = me.tenant;
    if (!tenant) {
      host.appendChild(el('div', { class: 'card' }, '<div class="help">当前账号未绑定租户（平台管理员视角）。请切换到租户账号，或由管理员在「租户管理」中为租户配置前缀。</div>'));
      return;
    }
    const isTenantUser = me.user.role === 'tenant';

    host.appendChild(el('div', { class: 'section-title' }, 'DoT 前缀定制'));
    host.appendChild(el('div', { class: 'section-sub' }, '客户端通过自定义前缀接入：' + esc(tenant.prefix + '.' + tenant.base_domain) + ' · 前缀由租户自助定制，前后端隔离，所有变更留痕审计'));

    // 前缀定制卡片
    const card = el('div', { class: 'card' });
    card.appendChild(el('h3', {}, '自定义前缀 <span class="hint">3-32 位小写字母/数字/连字符，不可使用保留词（www/api/admin/dns/ns1/ns2/mail/static/cdn/vip）</span>'));
    const row = el('div', { class: 'row' });
    const input = el('input', { type: 'text', value: tenant.prefix || '', placeholder: '例如 acme-gov', maxlength: '32' });
    input.style.width = '220px';
    const hint = el('span', { class: 'tag' });
    const updateHint = () => {
      const v = input.value.trim();
      const err = validatePrefix(v);
      hint.textContent = err ? '✗ ' + err : '✓ 可用：' + v + '.' + tenant.base_domain;
      hint.style.color = err ? 'var(--err)' : 'var(--ok)';
      saveBtn.disabled = !!err;
    };
    input.addEventListener('input', () => {
      input.value = normalizePrefix(input.value); // 自动小写、去非法字符
      updateHint();
    });
    row.appendChild(input);
    row.appendChild(hint);
    row.appendChild(el('span', { class: 'tag' }, '.' + esc(tenant.base_domain)));
    const saveBtn = el('button', { class: 'btn btn-primary' }, '保存前缀');
    saveBtn.onclick = async () => {
      try {
        const updated = await post('/api/v1/tenants/' + tenant.id + '/dot', { prefix: input.value.trim() });
        toastOk('前缀已更新：' + updated.prefix + '.' + updated.base_domain);
        setTimeout(() => location.reload(), 800);
      } catch (e) { toastErr(e.message); }
    };
    row.appendChild(saveBtn);
    card.appendChild(row);
    updateHint();

    // 协议开关
    const sw = el('div', { class: 'row' });
    const mkSwitch = (label, key) => {
      const lab = el('label', { class: 'switch' });
      const chk = el('input', { type: 'checkbox', checked: !!tenant[key] });
      chk.onchange = async () => {
        try {
          const body = {}; body[key] = chk.checked;
          await post('/api/v1/tenants/' + tenant.id + '/dot', body);
          toastOk(label + ' 已' + (chk.checked ? '启用' : '停用'));
        } catch (e) { chk.checked = !chk.checked; toastErr(e.message); }
      };
      lab.appendChild(chk);
      lab.appendChild(el('span', {}, esc(label)));
      return lab;
    };
    sw.appendChild(mkSwitch('DoT (853)', 'dot_enabled'));
    sw.appendChild(mkSwitch('DoH (443)', 'doh_enabled'));
    sw.appendChild(mkSwitch('DoQ (853/QUIC)', 'doq_enabled'));
    card.appendChild(sw);
    host.appendChild(card);

    // 端点展示
    const eps = await get('/api/v1/tenants/' + tenant.id + '/endpoints').catch(() => null);
    if (eps) {
      const epCard = el('div', { class: 'card' });
      epCard.appendChild(el('h3', {}, '部署端点 <span class="hint">客户端可直接使用的接入地址</span>'));
      const ep = (label, value) => {
        const box = el('div', { class: 'endpoint-box' });
        box.appendChild(el('div', { class: 'ep-label' }, label));
        box.appendChild(el('div', { class: 'ep-value' }, esc(value)));
        box.appendChild(copyBtn(value, '复制'));
        return box;
      };
      epCard.appendChild(ep('DoT 端点 (Android 私密 DNS / iOS)', eps.dot_endpoint + ':' + eps.dot_port));
      epCard.appendChild(ep('DoH 端点 (浏览器 / curl)', eps.doh_endpoint));
      if (tenant.doq_enabled) epCard.appendChild(ep('DoQ 端点 (RFC 9250)', eps.doq_endpoint));
      host.appendChild(epCard);

      // 客户端配置
      const cfgCard = el('div', { class: 'card' });
      cfgCard.appendChild(el('h3', {}, '客户端配置生成（一键部署）'));
      const tabs = [
        ['Android 私密 DNS', '设置 → 网络 → 私密 DNS → 输入：\n' + eps.dot_endpoint],
        ['Windows / macOS', '网络适配器 → DNS → 使用 DoT 服务器：\n' + eps.dot_endpoint + '\n（需支持 DoT 的系统版本）'],
        ['dig (DoT)', 'dig @' + eps.dot_endpoint + ' -p ' + eps.dot_port + ' +tls example.com A'],
        ['curl (DoH)', 'curl -H "accept: application/dns-message" -H "content-type: application/dns-message" \\\n  --data-binary @query.bin ' + eps.doh_endpoint],
        ['DoH JSON 模式', 'curl "' + eps.doh_endpoint.replace('/dns-query', '/resolve?name=example.com&type=A') + '"'],
        ['nginx 反代片段', eps.nginx_snippet],
        ['Caddy 片段', eps.caddy_snippet]
      ];
      const pre = el('pre', { class: 'code' }, esc(tabs.map(t => '▶ ' + t[0] + '\n' + t[1]).join('\n\n')));
      cfgCard.appendChild(pre);
      cfgCard.appendChild(copyBtn(tabs.map(t => t[1]).join('\n\n'), '复制全部配置'));
      host.appendChild(cfgCard);
    }
  }
};

/* ============================ ECS 模拟 ============================ */
Views.simulate = {
  title: 'ECS 模拟',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, 'ECS 模拟（前端 ECS 模拟 / ECS 传递验证）'));
    host.appendChild(el('div', { class: 'section-sub' }, '输入域名与 EDNS Client Subnet，系统将按真实链路模拟：缓存查询 → 分流 → 上游 → DNSSEC，展示该子网下的解析结果与缓存/上游命中路径。'));

    const card = el('div', { class: 'card' });
    const row = el('div', { class: 'row' });
    const qname = el('input', { type: 'text', placeholder: '域名，如 www.example.com', value: 'www.example.com' });
    qname.style.width = '260px';
    const qtype = el('select', {});
    ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'HTTPS'].forEach(t => qtype.appendChild(el('option', { value: t }, t)));
    const ecs = el('input', { type: 'text', placeholder: 'ECS 子网，如 203.0.113.0/24（可留空）' });
    ecs.style.width = '220px';
    const flush = el('label', { class: 'switch' });
    const flushChk = el('input', { type: 'checkbox' });
    flush.appendChild(flushChk); flush.appendChild(el('span', {}, '先清缓存（冷路径模拟）'));
    const btn = el('button', { class: 'btn btn-primary' }, '开始模拟');
    row.appendChild(qname); row.appendChild(qtype); row.appendChild(ecs); row.appendChild(flush); row.appendChild(btn);
    card.appendChild(row);
    const result = el('div', {});
    card.appendChild(result);
    host.appendChild(card);

    btn.onclick = async () => {
      result.innerHTML = '<div class="empty">模拟中…</div>';
      try {
        const r = await post('/api/v1/dns/simulate', {
          qname: qname.value.trim(), qtype: qtype.value, ecs: ecs.value.trim(), flush: flushChk.checked
        });
        const hits = r.cache_hit ? badgeOk('缓存命中') : badgeWarn('缓存未命中（回源）');
        const dnssec = r.dnssec_validated ? badgeOk('已验证') : badgeMuted('未验证');
        const vip = r.vip ? badgeVip('VIP') : '';
        result.innerHTML =
          '<div class="grid grid-3" style="margin-top:14px">' +
          statCard('结果', r.rcode || '-', 'RCODE').outerHTML +
          statCard('缓存', hits.replace(/<[^>]+>/g, ''), r.cache_hit ? '直接返回' : '回源获取').outerHTML +
          statCard('耗时', r.rtt_ms + ' ms', '全链路').outerHTML +
          '</div>' +
          '<table style="margin-top:14px"><tr><th>项目</th><th>值</th></tr>' +
          '<tr><td>请求 ECS</td><td class="mono">' + esc(r.ecs_requested || '(无)') + '</td></tr>' +
          '<tr><td>实际使用 ECS</td><td class="mono">' + esc(r.ecs_used || '(无)') + '</td></tr>' +
          '<tr><td>上游组（分流结果）</td><td class="mono">' + esc(r.upstream_group || '-') + ' <span class="tag">' + esc(r.rule_matched || '默认组') + '</span></td></tr>' +
          '<tr><td>上游节点</td><td class="mono">' + esc(r.upstream || '-') + '</td></tr>' +
          '<tr><td>DNSSEC</td><td>' + dnssec + ' ' + (r.dnssec_validated ? '' : '<span class="tag">（' + esc(DNSSEC_MODE_HINT) + '）</span>') + '</td></tr>' +
          '<tr><td>租户</td><td>' + esc(r.tenant_name || '-') + ' ' + vip + '</td></tr>' +
          '</table>' +
          (r.answers && r.answers.length ? '<pre class="code" style="margin-top:12px">' +
            esc(r.answers.map(a => a.name + '\t' + a.ttl + '\tIN\t' + a.type + '\t' + a.data).join('\n')) + '</pre>'
            : '<div class="empty">无应答记录</div>');
      } catch (e) {
        result.innerHTML = '<div class="form-msg">' + esc(e.message) + '</div>';
      }
    };
    btn.click();
  }
};
const DNSSEC_MODE_HINT = '由上游验证或本地 RRSIG 校验';

/* ============================ 上游与分流 ============================ */
Views.upstreams = {
  title: '上游与分流',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, '上游与分流'));
    host.appendChild(el('div', { class: 'section-sub' }, '上游支持 UDP / TCP / DoT / DoH / DoQ 五种协议，健康检查自动摘除故障节点；分流规则支持后缀/前缀/精确/正则，优先级高者先匹配。所有变更即时热加载。'));

    const groups = await get('/api/v1/groups').catch(() => []);
    const rules = await get('/api/v1/rules').catch(() => []);
    const protoLabel = p => ({ udp: 'UDP', tcp: 'TCP', dot: 'DoT', doh: 'DoH', doq: 'DoQ' }[p] || p);

    // 上游组 + 成员
    const gCard = el('div', { class: 'card' });
    gCard.appendChild(el('h3', {}, '上游组与成员 <span class="hint">健康状态由 30s 周期探测维护</span>'));
    const gRows = groups.map(g => ({
      name: g.name, strategy: g.strategy, tenant_id: g.tenant_id, id: g.id,
      ups: (g.upstreams || []).map(u =>
        '<div style="margin:3px 0;display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        '<span class="badge ' + (u.enabled ? 'badge-info' : 'badge-muted') + '">' + esc(protoLabel(u.protocol)) + '</span> ' +
        '<span class="mono">' + esc(u.name) + '</span> ' +
        '<span class="tag mono">' + esc(u.address + ':' + u.port) + (u.hostname && u.hostname !== u.address ? ' (' + esc(u.hostname) + ')' : '') + '</span>' +
        (u.healthy === undefined ? '' : (u.healthy ? badgeOk('健康') : badgeErr('故障'))) +
        (u.weight > 1 ? ' <span class="tag">权重 ' + u.weight + '</span>' : '') +
        '<button class="btn btn-sm btn-ghost" data-up="' + esc(u.id) + '" data-act="up-edit">编辑</button>' +
        '<button class="btn btn-sm btn-danger" data-up="' + esc(u.id) + '" data-act="up-del">删</button>' +
        '</div>'
      ).join('') || '<span class="tag">（空组）</span>'
    }));
    gCard.insertAdjacentHTML('beforeend', table(
      [{ t: '组名 / 策略', f: r =>
           '<b>' + esc(r.name) + '</b> ' +
           '<button class="btn btn-sm btn-ghost" data-g="' + esc(r.id) + '" data-act="g-edit">编辑</button> ' +
           '<button class="btn btn-sm btn-danger" data-g="' + esc(r.id) + '" data-act="g-del">删</button>' +
           '<br><span class="tag">' + esc(r.strategy) + (r.tenant_id ? ' · 租户专属' : ' · 全局') + '</span>' },
       { t: '成员（协议 · 地址 · 健康）', f: r => r.ups },
       { t: '添加成员', f: r => '<button class="btn btn-sm btn-primary" data-g="' + esc(r.id) + '" data-act="up-add">+ 上游</button>' }],
      gRows, '暂无上游组'
    ));
    gCard.querySelectorAll('button[data-act]').forEach(b => b.onclick = async () => {
      const act = b.dataset.act, id = b.dataset.g || b.dataset.up;
      if (act === 'g-edit') {
        const g = groups.find(x => x.id === id);
        modal('编辑上游组', [
          { key: 'name', label: '组名', value: g.name },
          { key: 'strategy', label: '策略', type: 'select', options: [['weighted', '加权'], ['round_robin', '轮询'], ['failover', '故障优先']], value: g.strategy },
          { key: 'health_domain', label: '健康探测域名（可选）', value: g.health_domain || '' }
        ], g, async v => { await put('/api/v1/groups/' + g.id, v); toastOk('组已更新并热加载'); renderView('upstreams'); });
      } else if (act === 'g-del') {
        if (!confirm('确认删除该组及其全部成员？')) return;
        await del('/api/v1/groups/' + id); toastOk('已删除'); renderView('upstreams');
      } else if (act === 'up-add') {
        modal('添加上游成员', [
          { key: 'name', label: '名称' },
          { key: 'protocol', label: '协议', type: 'select', options: [['udp', 'UDP'], ['tcp', 'TCP'], ['dot', 'DoT'], ['doh', 'DoH'], ['doq', 'DoQ']] },
          { key: 'address', label: '地址（IP 或域名）' },
          { key: 'port', label: '端口（留空自动）', type: 'number', def: '' },
          { key: 'hostname', label: 'TLS SNI / DoH Host（可选）' },
          { key: 'weight', label: '权重', type: 'number', def: 1 },
          { key: 'enabled', label: '启用', type: 'checkbox', def: true }
        ], null, async v => {
          await post('/api/v1/upstreams', Object.assign({ group_id: id }, v, { port: v.port ? parseInt(v.port) : 0, weight: parseInt(v.weight) || 1 }));
          toastOk('成员已添加并热加载'); renderView('upstreams');
        });
      } else if (act === 'up-edit') {
        const u = groups.flatMap(g => g.upstreams || []).find(x => x.id === id);
        if (!u) return;
        modal('编辑上游成员', [
          { key: 'name', label: '名称', value: u.name },
          { key: 'protocol', label: '协议', type: 'select', options: [['udp', 'UDP'], ['tcp', 'TCP'], ['dot', 'DoT'], ['doh', 'DoH'], ['doq', 'DoQ']], value: u.protocol },
          { key: 'address', label: '地址', value: u.address },
          { key: 'port', label: '端口', type: 'number', value: u.port },
          { key: 'hostname', label: 'TLS SNI / DoH Host', value: u.hostname || '' },
          { key: 'weight', label: '权重', type: 'number', value: u.weight },
          { key: 'enabled', label: '启用', type: 'checkbox', value: u.enabled }
        ], u, async v => {
          await put('/api/v1/upstreams/' + u.id, Object.assign({ group_id: u.group_id }, v, { port: parseInt(v.port) || 0, weight: parseInt(v.weight) || 1 }));
          toastOk('成员已更新并热加载'); renderView('upstreams');
        });
      } else if (act === 'up-del') {
        if (!confirm('确认删除该上游成员？')) return;
        await del('/api/v1/upstreams/' + id); toastOk('已删除'); renderView('upstreams');
      }
    });
    host.appendChild(gCard);

    // 新建组
    const addGCard = el('div', { class: 'card' });
    addGCard.appendChild(el('h3', {}, '新建上游组'));
    const gRow = el('div', { class: 'row' });
    const gName = el('input', { type: 'text', placeholder: '组名（如 domestic-vip）' }); gName.style.width = '200px';
    const gStrat = el('select', {});
    [['weighted', '加权'], ['round_robin', '轮询'], ['failover', '故障优先']].forEach(([v, t]) => gStrat.appendChild(el('option', { value: v }, t)));
    const gBtn = el('button', { class: 'btn btn-primary' }, '创建组');
    gBtn.onclick = async () => {
      try {
        await post('/api/v1/groups', { name: gName.value.trim(), strategy: gStrat.value });
        toastOk('组已创建'); renderView('upstreams');
      } catch (e) { toastErr(e.message); }
    };
    gRow.appendChild(gName); gRow.appendChild(gStrat); gRow.appendChild(gBtn);
    addGCard.appendChild(gRow);
    host.appendChild(addGCard);

    // 分流规则（增删改）
    const rCard = el('div', { class: 'card' });
    rCard.appendChild(el('h3', {}, '分流规则 <span class="hint">租户级规则优先于全局规则</span>'));
    const rRows = rules.map(r => ({
      name: r.name, match_type: r.match_type, match_value: r.match_value,
      group: groups.find(g => g.id === r.group_id), priority: r.priority, enabled: r.enabled,
      tenant_id: r.tenant_id, id: r.id
    }));
    rCard.insertAdjacentHTML('beforeend', table(
      [{ t: '规则名', f: r => esc(r.name) + (r.tenant_id ? ' <span class="badge badge-vip">租户</span>' : ' <span class="badge badge-info">全局</span>') },
       { t: '匹配方式', f: r => badgeInfo(r.match_type) },
       { t: '匹配值', f: r => '<span class="mono">' + esc(r.match_value) + '</span>' },
       { t: '目标组', f: r => esc(r.group ? r.group.name : r.group_id) },
       { t: '优先级', f: r => esc(r.priority) },
       { t: '状态', f: r => boolBadge(r.enabled) },
       { t: '操作', f: r =>
           '<button class="btn btn-sm btn-ghost" data-rule="' + esc(r.id) + '" data-act="r-edit">编辑</button> ' +
           '<button class="btn btn-sm btn-danger" data-rule="' + esc(r.id) + '" data-act="r-del">删</button>' }],
      rRows, '暂无分流规则'
    ));
    rCard.querySelectorAll('button[data-act]').forEach(b => b.onclick = async () => {
      const r = rules.find(x => x.id === b.dataset.rule);
      if (b.dataset.act === 'r-edit') {
        modal('编辑分流规则', [
          { key: 'name', label: '规则名', value: r.name },
          { key: 'match_type', label: '匹配方式', type: 'select', options: [['suffix', '后缀'], ['prefix', '前缀'], ['exact', '精确'], ['regex', '正则'], ['all', '全部']], value: r.match_type },
          { key: 'match_value', label: '匹配值', value: r.match_value },
          { key: 'group_id', label: '目标组', type: 'select', options: groups.map(g => [g.id, g.name]), value: r.group_id },
          { key: 'priority', label: '优先级', type: 'number', value: r.priority },
          { key: 'enabled', label: '启用', type: 'checkbox', value: r.enabled }
        ], r, async v => { await put('/api/v1/rules/' + r.id, v); toastOk('规则已更新并热加载'); renderView('upstreams'); });
      } else if (b.dataset.act === 'r-del') {
        if (!confirm('确认删除该规则？')) return;
        await del('/api/v1/rules/' + r.id); toastOk('已删除'); renderView('upstreams');
      }
    });
    host.appendChild(rCard);

    // 新增规则
    const addCard = el('div', { class: 'card' });
    addCard.appendChild(el('h3', {}, '新增分流规则'));
    const row = el('div', { class: 'row' });
    const name = el('input', { type: 'text', placeholder: '规则名' }); name.style.width = '150px';
    const mt = el('select', {});
    [['suffix', '后缀匹配'], ['prefix', '前缀匹配'], ['exact', '精确匹配'], ['regex', '正则匹配'], ['all', '全部流量']].forEach(([v, t]) => mt.appendChild(el('option', { value: v }, t)));
    const mv = el('input', { type: 'text', placeholder: '匹配值，如 cn 或 *.example.com' }); mv.style.width = '220px';
    const gsel = el('select', {});
    groups.forEach(g => gsel.appendChild(el('option', { value: g.id }, g.name)));
    const pr = el('input', { type: 'number', value: '50', style: 'width:80px' });
    const add = el('button', { class: 'btn btn-primary' }, '添加');
    add.onclick = async () => {
      try {
        await post('/api/v1/rules', { name: name.value.trim() || 'rule', match_type: mt.value, match_value: mv.value.trim(), group_id: gsel.value, priority: parseInt(pr.value) || 0, enabled: true });
        toastOk('规则已添加并热加载');
        renderView('upstreams');
      } catch (e) { toastErr(e.message); }
    };
    row.appendChild(name); row.appendChild(mt); row.appendChild(mv); row.appendChild(gsel);
    row.appendChild(el('span', { class: 'tag' }, '优先级')); row.appendChild(pr); row.appendChild(add);
    addCard.appendChild(row);
    host.appendChild(addCard);
  }
};

/* ============================ 缓存与预热 ============================ */
Views.cache = {
  title: '缓存与预热',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, 'Redis 缓存与动态预热'));
    host.appendChild(el('div', { class: 'section-sub' }, '缓存以「租户 + ECS 子网」为粒度；活跃 ECS 自动追踪，热域名可一键跨 ECS 预热，近过期热点自动异步刷新。'));

    const stats = await get('/api/v1/cache/stats').catch(() => ({}));
    const grid = el('div', { class: 'grid grid-4' });
    grid.appendChild(statCard('缓存驱动', stats.cache_driver || '-', '生产为 Redis'));
    grid.appendChild(statCard('活跃 ECS 子网', fmtNum(stats.active_ecs), 'Redis 集合追踪'));
    grid.appendChild(statCard('DNSSEC 校验通过', fmtNum(stats.dnssec_ok ? stats.dnssec_ok.verified : 0), 'RRset 级'));
    grid.appendChild(statCard('日志落库(批)', fmtNum(stats.log_flushed), '异步批量写入'));
    host.appendChild(grid);

    // 清理
    const purgeCard = el('div', { class: 'card' });
    purgeCard.appendChild(el('h3', {}, '缓存清理'));
    const row = el('div', { class: 'row' });
    const tid = el('input', { type: 'text', placeholder: '租户 ID（留空=全部）' }); tid.style.width = '220px';
    const qn = el('input', { type: 'text', placeholder: '域名（可选）' }); qn.style.width = '200px';
    const btn = el('button', { class: 'btn btn-danger' }, '清理缓存');
    btn.onclick = async () => {
      try {
        const r = await post('/api/v1/cache/purge', { tenant_id: tid.value.trim(), qname: qn.value.trim() });
        toastOk('已清理 ' + r.deleted + ' 条缓存');
      } catch (e) { toastErr(e.message); }
    };
    row.appendChild(tid); row.appendChild(qn); row.appendChild(btn);
    purgeCard.appendChild(row);
    host.appendChild(purgeCard);

    // 手动预热
    const warmCard = el('div', { class: 'card' });
    warmCard.appendChild(el('h3', {}, 'ECS 动态预热 <span class="hint">按活跃 ECS 子网预热热点域名</span>'));
    const wrow = el('div', { class: 'row' });
    const wtid = el('input', { type: 'text', placeholder: '租户 ID' }); wtid.style.width = '200px';
    const wdom = el('input', { type: 'text', placeholder: '域名，逗号分隔（如 example.com,api.example.com）' }); wdom.style.width = '360px';
    const wecs = el('input', { type: 'text', placeholder: 'ECS 列表（留空=自动使用活跃 ECS）' }); wecs.style.width = '280px';
    const wbtn = el('button', { class: 'btn btn-primary' }, '启动预热');
    wbtn.onclick = async () => {
      try {
        const domains = wdom.value.split(',').map(s => s.trim()).filter(Boolean);
        const ecsList = wecs.value.split(',').map(s => s.trim()).filter(Boolean);
        const j = await post('/api/v1/cache/warm', { tenant_id: wtid.value.trim(), domains, ecs: ecsList });
        toastOk('预热任务已启动：' + j.total + ' 个 (域名×ECS) 组合');
        renderView('cache');
      } catch (e) { toastErr(e.message); }
    };
    wrow.appendChild(wtid); wrow.appendChild(wdom); wrow.appendChild(wecs); wrow.appendChild(wbtn);
    warmCard.appendChild(wrow);
    warmCard.appendChild(el('div', { class: 'help', style: 'margin-top:8px' },
      '💡 租户页面还提供「一键预热该租户全部热域名」：POST /api/v1/tenants/{id}/warm — 自动取该租户热域名 × 活跃 ECS 集合。'));
    host.appendChild(warmCard);

    // 预热任务
    const jobs = await get('/api/v1/cache/warm-jobs').catch(() => []);
    const jCard = el('div', { class: 'card' });
    jCard.appendChild(el('h3', {}, '预热任务'));
    jCard.insertAdjacentHTML('beforeend', table(
      [{ t: '任务 ID', f: r => '<span class="mono">' + esc(r.id.slice(0, 8)) + '</span>' },
       { t: '租户', f: r => esc(r.tenant_id.slice(0, 8)) },
       { t: '进度', f: r => esc(r.done + ' / ' + r.total) },
       { t: '失败', f: r => esc(r.failed) },
       { t: 'ECS 数', f: r => esc((r.ecs_list || []).length) },
       { t: '状态', f: r => r.finished ? badgeOk('完成') : badgeWarn('进行中') },
       { t: '开始时间', f: r => fmtTime(r.started_at) }],
      jobs, '暂无预热任务'
    ));
    host.appendChild(jCard);

    // 热域名
    const hots = await get('/api/v1/hot-domains').catch(() => []);
    const hCard = el('div', { class: 'card' });
    hCard.appendChild(el('h3', {}, '热域名清单 <span class="hint">预热与自适应刷新的数据源</span>'));
    const hrow = el('div', { class: 'row' });
    const hdom = el('input', { type: 'text', placeholder: '域名' }); hdom.style.width = '240px';
    const hbtn = el('button', { class: 'btn btn-primary' }, '添加');
    hbtn.onclick = async () => {
      try {
        await post('/api/v1/hot-domains', { domain: hdom.value.trim(), weight: 10, enabled: true });
        toastOk('已添加热域名');
        renderView('cache');
      } catch (e) { toastErr(e.message); }
    };
    hrow.appendChild(hdom); hrow.appendChild(hbtn);
    hCard.appendChild(hrow);
    hCard.insertAdjacentHTML('beforeend', table(
      [{ t: '域名', f: r => '<span class="mono">' + esc(r.domain) + '</span>' + (r.tenant_id ? ' <span class="badge badge-vip">租户</span>' : ' <span class="badge badge-info">全局</span>') },
       { t: '权重', f: r => esc(r.weight) },
       { t: '状态', f: r => boolBadge(r.enabled) },
       { t: '操作', f: r => '<button class="btn btn-sm btn-danger" data-id="' + esc(r.id) + '">删除</button>' }],
      hots, '暂无热域名'
    ));
    hCard.querySelectorAll('button[data-id]').forEach(b => b.onclick = async () => {
      try { await del('/api/v1/hot-domains/' + b.dataset.id); toastOk('已删除'); renderView('cache'); } catch (e) { toastErr(e.message); }
    });
    host.appendChild(hCard);
  }
};

/* ============================ 日志查询 ============================ */
Views.logs = {
  title: '日志查询',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, '查询日志（MySQL）'));
    host.appendChild(el('div', { class: 'section-sub' }, '全量查询审计，异步批量落库，支持按租户 / 域名 / 类型 / 时间过滤。'));

    const card = el('div', { class: 'card' });
    const row = el('div', { class: 'row' });
    const qname = el('input', { type: 'text', placeholder: '域名关键字' }); qname.style.width = '180px';
    const qtype = el('select', {}); qtype.appendChild(el('option', { value: '' }, '全部类型'));
    ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'HTTPS'].forEach(t => qtype.appendChild(el('option', { value: t }, t)));
    const from = el('input', { type: 'datetime-local' });
    const to = el('input', { type: 'datetime-local' });
    const btn = el('button', { class: 'btn btn-primary' }, '查询');
    row.appendChild(qname); row.appendChild(qtype);
    row.appendChild(el('span', { class: 'tag' }, '从')); row.appendChild(from);
    row.appendChild(el('span', { class: 'tag' }, '至')); row.appendChild(to);
    row.appendChild(btn);
    card.appendChild(row);
    const box = el('div', {});
    card.appendChild(box);
    host.appendChild(card);

    let page = 0;
    const LIMIT = 100;
    const load = async () => {
      const q = new URLSearchParams({ limit: LIMIT, offset: page * LIMIT });
      if (qname.value.trim()) q.set('qname', qname.value.trim());
      if (qtype.value) q.set('qtype', qtype.value);
      if (from.value) q.set('from', new Date(from.value).toISOString().slice(0, 19));
      if (to.value) q.set('to', new Date(to.value).toISOString().slice(0, 19));
      try {
        const r = await get('/api/v1/logs/query?' + q.toString());
        const rows = r.rows || [];
        box.innerHTML = table(
          [{ t: '时间', f: r => fmtTime(r.ts) },
           { t: '客户端', f: r => '<span class="mono">' + esc(r.client_ip) + '</span>' },
           { t: 'ECS', f: r => r.ecs ? '<span class="mono">' + esc(r.ecs) + '</span>' : '-' },
           { t: '域名', f: r => '<span class="mono">' + esc(r.qname) + '</span>' },
           { t: '类型', f: r => badgeInfo(r.qtype) },
           { t: 'RCODE', f: r => esc(r.rcode) },
           { t: '缓存', f: r => r.cache_hit ? badgeOk('命中') : badgeMuted('回源') },
           { t: '上游', f: r => '<span class="tag">' + esc(r.upstream_group || '-') + '</span> <span class="mono">' + esc(r.upstream || '-') + '</span>' },
           { t: '耗时', f: r => esc(r.rtt_ms) + 'ms' },
           { t: '通道', f: r => badgeMuted(r.via) },
           { t: 'DNSSEC', f: r => r.dnssec_ok ? badgeOk('✓') : '-' }],
          rows, '暂无日志'
        ) + '<div class="pager"><button class="btn btn-sm" id="lg-prev">上一页</button>' +
          '<span>第 ' + (page + 1) + ' 页 · 共 ' + fmtNum(r.total) + ' 条</span>' +
          '<button class="btn btn-sm" id="lg-next">下一页</button></div>';
        const prev = box.querySelector('#lg-prev'), next = box.querySelector('#lg-next');
        if (prev) prev.onclick = () => { if (page > 0) { page--; load(); } };
        if (next) next.onclick = () => { if ((page + 1) * LIMIT < r.total) { page++; load(); } };
      } catch (e) { box.innerHTML = '<div class="form-msg">' + esc(e.message) + '</div>'; }
    };
    btn.onclick = () => { page = 0; load(); };
    load();
  }
};

/* ============================ 租户管理 ============================ */
Views.tenants = {
  title: '租户管理',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, '租户管理'));
    host.appendChild(el('div', { class: 'section-sub' }, '每个租户拥有独立 DoT/DoH 前缀、缓存命名空间、限流与上游通道；VIP 租户启用高价值专用通道。'));

    const tenants = await get('/api/v1/tenants');
    const card = el('div', { class: 'card' });
    card.insertAdjacentHTML('beforeend', table(
      [{ t: '租户', f: r => '<b>' + esc(r.name) + '</b><br><span class="tag mono">' + esc(r.id.slice(0, 8)) + '</span>' },
       { t: 'DoT 前缀', f: r => r.prefix ? '<span class="mono">' + esc(r.prefix + '.' + r.base_domain) + '</span>' : badgeWarn('未配置') },
       { t: '通道', f: r => (r.vip ? badgeVip('VIP 专用') : badgeInfo('标准')) + (r.enabled ? ' ' + badgeOk('启用') : ' ' + badgeErr('停用')) },
       { t: '协议', f: r => [r.dot_enabled && 'DoT', r.doh_enabled && 'DoH', r.doq_enabled && 'DoQ'].filter(Boolean).map(badgeInfo).join(' ') },
       { t: '限流 QPS', f: r => esc(r.rate_limit_qps) },
       { t: 'ECS', f: r => r.default_ecs ? '<span class="mono">' + esc(r.default_ecs) + '</span>' : (r.allow_ecs ? '客户端自定义' : '禁用') },
       { t: '操作', f: r =>
         '<button class="btn btn-sm" data-act="edit" data-id="' + esc(r.id) + '">编辑</button> ' +
         '<button class="btn btn-sm" data-act="warm" data-id="' + esc(r.id) + '">预热</button> ' +
         '<button class="btn btn-sm btn-danger" data-act="del" data-id="' + esc(r.id) + '">删除</button>' }],
      tenants, '暂无租户'
    ));
    card.querySelectorAll('button[data-act]').forEach(b => b.onclick = async () => {
      const id = b.dataset.id;
      try {
        if (b.dataset.act === 'warm') {
          const j = await post('/api/v1/tenants/' + id + '/warm', {});
          toastOk('预热已启动：' + j.total + ' 组合');
        } else if (b.dataset.act === 'del') {
          if (!confirm('确认删除该租户？此操作不可恢复。')) return;
          await del('/api/v1/tenants/' + id);
          toastOk('已删除');
          renderView('tenants');
        } else if (b.dataset.act === 'edit') {
          const t = tenants.find(x => x.id === id);
          if (!t) return;
          modal('编辑租户（' + t.name + '）', [
            { key: 'name', label: '租户名称', value: t.name },
            { key: 'prefix', label: 'DoT 前缀（3-32 位小写字母/数字/连字符）', value: t.prefix,
              validate: v => validatePrefix(v.trim()) },
            { key: 'base_domain', label: '基域', value: t.base_domain },
            { key: 'enabled', label: '启用', type: 'checkbox', value: t.enabled },
            { key: 'vip', label: 'VIP 专用通道（专属上游组 + 10× 限流）', type: 'checkbox', value: t.vip },
            { key: 'rate_limit_qps', label: '限流 QPS（每客户端 IP）', type: 'number', value: t.rate_limit_qps },
            { key: 'cache_max_ttl', label: '缓存 TTL 上限（秒）', type: 'number', value: t.cache_max_ttl },
            { key: 'default_ecs', label: '默认 ECS（如 116.62.52.0/24，留空不强制）', value: t.default_ecs || '' },
            { key: 'allow_ecs', label: '接受客户端自定义 ECS', type: 'checkbox', value: t.allow_ecs },
            { key: 'dot_enabled', label: 'DoT 启用', type: 'checkbox', value: t.dot_enabled },
            { key: 'doh_enabled', label: 'DoH 启用', type: 'checkbox', value: t.doh_enabled },
            { key: 'doq_enabled', label: 'DoQ 启用', type: 'checkbox', value: t.doq_enabled },
            { key: 'upstream_group', label: '固定上游组 ID（VIP 专用通道，留空=走分流规则）', value: t.upstream_group || '' }
          ], t, async v => {
            v.rate_limit_qps = parseInt(v.rate_limit_qps) || 100;
            v.cache_max_ttl = parseInt(v.cache_max_ttl) || 21600;
            await put('/api/v1/tenants/' + id, v);
            toastOk('租户已更新并热加载');
            renderView('tenants');
          });
        }
      } catch (e) { toastErr(e.message); }
    });
    host.appendChild(card);

    // 新建租户
    const add = el('div', { class: 'card' });
    add.appendChild(el('h3', {}, '新建租户'));
    const row = el('div', { class: 'row' });
    const name = el('input', { type: 'text', placeholder: '租户名称' }); name.style.width = '160px';
    const prefix = el('input', { type: 'text', placeholder: '前缀（如 acme-gov）' }); prefix.style.width = '160px';
    const base = el('input', { type: 'text', value: 'dns.example.com' }); base.style.width = '180px';
    const vip = el('label', { class: 'switch' });
    const vipChk = el('input', { type: 'checkbox' });
    vip.appendChild(vipChk); vip.appendChild(el('span', {}, 'VIP 专用通道'));
    const btn = el('button', { class: 'btn btn-primary' }, '创建');
    btn.onclick = async () => {
      try {
        const r = await post('/api/v1/tenants', {
          name: name.value.trim(), prefix: prefix.value.trim(), base_domain: base.value.trim(),
          enabled: true, vip: vipChk.checked, rate_limit_qps: 100, cache_max_ttl: 21600,
          allow_ecs: true, dot_enabled: true, doh_enabled: true, doq_enabled: true
        });
        const t = r.tenant || r;
        toast('租户已创建：' + t.prefix + '.' + t.base_domain + '\n\n租户管理员账号：' + (r.initial_username || '') + '\n初始密码：' + (r.initial_password || '') + '\n（请立即告知租户，建议登录后修改）', 'ok');
        renderView('tenants');
      } catch (e) { toastErr(e.message); }
    };
    row.appendChild(name); row.appendChild(prefix); row.appendChild(base); row.appendChild(vip); row.appendChild(btn);
    add.appendChild(row);
    host.appendChild(add);
  }
};

/* ============================ 用户管理 ============================ */
Views.users = {
  title: '用户管理',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, '用户管理'));
    host.appendChild(el('div', { class: 'section-sub' }, 'bcrypt 密码存储、登录锁定、按 IP 限速；角色：admin（平台） / tenant（租户）。'));

    const users = await get('/api/v1/users');
    const tenants = await get('/api/v1/tenants').catch(() => []);
    const tenantName = id => { const t = tenants.find(x => x.id === id); return t ? t.name : '-'; };
    const card = el('div', { class: 'card' });
    card.insertAdjacentHTML('beforeend', table(
      [{ t: '用户名', f: r => '<b>' + esc(r.username) + '</b>' + (r.role === 'admin' ? ' ' + badgeVip('管理员') : ' ' + badgeInfo('租户')) },
       { t: '所属租户', f: r => r.tenant_id
           ? '<span class="mono">' + esc(tenantName(r.tenant_id)) + '</span> <span class="tag">' + esc(r.tenant_id.slice(0, 8)) + '</span>'
           : badgeMuted('平台（未绑定）') },
       { t: '邮箱', f: r => esc(r.email || '-') },
       { t: '最后登录', f: r => fmtTime(r.last_login) },
       { t: '操作', f: r =>
           '<button class="btn btn-sm" data-edit="' + esc(r.id) + '">编辑/改绑</button> ' +
           '<button class="btn btn-sm" data-reset="' + esc(r.id) + '">重置密码</button>' }],
      users, '暂无用户'
    ));
    card.querySelectorAll('button[data-edit]').forEach(b => b.onclick = () => {
      const u = users.find(x => x.id === b.dataset.edit);
      if (!u) return;
      modal('编辑用户（' + u.username + '）', [
        { key: 'role', label: '角色', type: 'select',
          options: [['tenant', '租户用户'], ['admin', '平台管理员']], value: u.role },
        { key: 'tenant_id', label: '归属租户（admin 也可绑定作默认视角；租户用户必须绑定）', type: 'select',
          options: [['', '— 不绑定（平台管理员）—']].concat(tenants.map(t => [t.id, t.name + ' (' + t.prefix + ')'])),
          value: u.tenant_id || '' },
        { key: 'email', label: '邮箱', value: u.email || '' }
      ], u, async v => {
        await put('/api/v1/users/' + u.id, v);
        toastOk('用户已更新（租户用户需重新登录后生效）');
        renderView('users');
      });
    });
    card.querySelectorAll('button[data-reset]').forEach(b => b.onclick = async () => {
      const pw = prompt('输入新密码（至少 12 位）:');
      if (!pw || pw.length < 12) { toastErr('密码至少 12 位'); return; }
      try { await post('/api/v1/users/' + b.dataset.reset + '/password', { password: pw }); toastOk('密码已重置'); } catch (e) { toastErr(e.message); }
    });
    host.appendChild(card);

    // 新建用户（实时校验）
    const add = el('div', { class: 'card' });
    add.appendChild(el('h3', {}, '新建用户'));
    const row = el('div', { class: 'row' });
    const u = el('input', { type: 'text', placeholder: '用户名（必填）' }); u.style.width = '150px';
    const p = el('input', { type: 'password', placeholder: '密码（≥12位）' }); p.style.width = '180px';
    const role = el('select', {});
    role.appendChild(el('option', { value: 'tenant' }, '租户用户'));
    role.appendChild(el('option', { value: 'admin' }, '平台管理员'));
    const tsel = el('select', {});
    tsel.appendChild(el('option', { value: '' }, '— 选择租户 —'));
    tenants.forEach(t => tsel.appendChild(el('option', { value: t.id }, t.name + ' (' + t.prefix + ')')));
    const msg = el('span', { class: 'tag' });
    const btn = el('button', { class: 'btn btn-primary' }, '创建');
    const recheck = () => {
      const errs = [];
      if (!u.value.trim()) errs.push('用户名必填');
      if (p.value.length < 12) errs.push('密码至少 12 位（当前 ' + p.value.length + ' 位）');
      if (role.value === 'tenant' && !tsel.value) errs.push('租户用户需选择租户');
      msg.textContent = errs.length ? '✗ ' + errs.join('；') : '✓ 可以创建';
      msg.style.color = errs.length ? 'var(--err)' : 'var(--ok)';
      btn.disabled = errs.length > 0;
    };
    u.addEventListener('input', recheck);
    p.addEventListener('input', recheck);
    role.addEventListener('change', recheck);
    tsel.addEventListener('change', recheck);
    btn.onclick = async () => {
      try {
        const created = await post('/api/v1/users', { username: u.value.trim(), password: p.value, role: role.value, tenant_id: role.value === 'tenant' ? tsel.value : '' });
        toastOk('用户已创建并绑定租户：' + created.username + (created.tenant_id ? ' → ' + tenantName(created.tenant_id) : ''));
        renderView('users');
      } catch (e) { toastErr(e.message); }
    };
    row.appendChild(u); row.appendChild(p); row.appendChild(role); row.appendChild(tsel); row.appendChild(btn); row.appendChild(msg);
    add.appendChild(row);
    add.appendChild(el('div', { class: 'help' },
      '💡 绑定租户 = 该账号登录后默认进入该租户视角（DoT 前缀/缓存/日志）；租户用户只能管理绑定租户，平台管理员（admin）拥有全部权限、绑定租户仅作归属。'));
    host.appendChild(add);
    recheck();
  }
};

/* ============================ 安全中心 ============================ */
Views.security = {
  title: '安全中心',
  async render(host) {
    host.appendChild(el('div', { class: 'section-title' }, '安全中心'));
    host.appendChild(el('div', { class: 'section-sub' }, '安全基线、审计日志与高价值专用通道说明。'));

    const card = el('div', { class: 'card' });
    card.appendChild(el('h3', {}, '安全基线（已内置）'));
    card.appendChild(el('div', { class: 'help' }, [
      '✅ <b>传输安全</b>：TLS 1.2+ / 强密码套件；DoT 未知前缀在 TLS 握手层直接拒绝（前缀不可枚举）',
      '✅ <b>认证</b>：JWT 15 分钟短时效 + 一次性 Refresh Token（Redis 存储）；bcrypt(12) 密码；连续 5 次失败锁定 15 分钟',
      '✅ <b>越权防护</b>：RBAC 角色隔离，租户用户只能操作自有租户资源（服务端强制 scope）',
      '✅ <b>注入防护</b>：全部 SQL 参数化；Redis key 白名单字符过滤；CORS 严格白名单',
      '✅ <b>限流</b>：DNS 平面按 租户×IP QPS 限流（Redis 跨实例）；登录接口按 IP 限速',
      '✅ <b>审计</b>：所有管理操作写入 audit_logs（只追加）',
      '✅ <b>数据面隔离</b>：DNS 请求路径只碰 Redis，绝不触达 MySQL；前后端分离，API 独立端口',
    ].join('<br>')));
    host.appendChild(card);

    const vipCard = el('div', { class: 'card vip-note' });
    vipCard.appendChild(el('h3', {}, '👑 政企高价值专用通道'));
    vipCard.appendChild(el('div', { class: 'help' }, [
      'VIP 租户（vip=true）自动获得：',
      '· <b>专用上游组</b>：tenants.upstream_group 固定路由，不与其他租户争抢',
      '· <b>10× 限流配额</b>：RateLimitVIPMult 可配置',
      '· <b>独立缓存命名空间</b>：dns:cache:{tenant} 前缀隔离',
      '· <b>专属管理通道</b>：API_ADMIN_LISTEN 独立端口，可启用 mTLS 客户端证书（API_MTLS_CA_FILE）',
      '· <b>预热优先</b>：租户级热域名 × 活跃 ECS 一键预热',
    ].join('<br>')));
    host.appendChild(vipCard);

    const audit = await get('/api/v1/logs/audit').catch(() => []);
    const aCard = el('div', { class: 'card' });
    aCard.appendChild(el('h3', {}, '审计日志（最近 200 条）'));
    aCard.insertAdjacentHTML('beforeend', table(
      [{ t: '时间', f: r => fmtTime(r.ts) },
       { t: '操作者', f: r => esc(r.actor_name || r.actor_id || '-') },
       { t: '动作', f: r => badgeInfo(r.action) },
       { t: '目标', f: r => '<span class="mono">' + esc(r.target || '-') + '</span>' },
       { t: 'IP', f: r => esc(r.client_ip || '-') }],
      audit, '暂无审计日志'
    ));
    host.appendChild(aCard);
  }
};

function renderView(name) {
  const v = Views[name];
  const content = document.getElementById('content');
  if (!v) { content.innerHTML = '<div class="empty">未知页面</div>'; return; }
  content.innerHTML = '';
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === name));
  v.render(content).catch(e => {
    content.innerHTML = '<div class="card"><div class="form-msg">' + esc(e.message) + '</div></div>';
  });
}
