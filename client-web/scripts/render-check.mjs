#!/usr/bin/env node
// DNSD 客户端门户 渲染自检脚本
// 无需真实后端：拦截 /api 请求并返回 mock 数据，验证各页面在真实浏览器中的渲染。
//
// 用法：
//   node scripts/render-check.mjs [baseUrl] [screenshotDir]
//   baseUrl        默认 http://localhost:8082（vite dev server）
//   screenshotDir  默认 系统临时目录/dnsd-render-check
//
// 前置（首次）：
//   1. npm install                # 安装含 playwright
//   2. npx playwright install chromium
//   3. npm run dev                # 另开一个终端

import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const BASE = process.argv[2] || 'http://localhost:8082'
const SHOT_DIR = process.argv[3] || join(tmpdir(), 'dnsd-render-check')
mkdirSync(SHOT_DIR, { recursive: true })

// ---------- mock 数据（对齐 apid 真实响应结构） ----------
const TENANT = {
  id: 't1', name: 'Acme 科技', prefix: 'acme-01', base_domain: 'dns.example.com',
  dot_enabled: true, doh_enabled: true, doq_enabled: true, vip: false,
  rate_limit_qps: 500, cache_max_ttl: 3600, default_ecs: '203.0.113.0/24', allow_ecs: true,
}

function mockRows() {
  const ips = ['203.0.113.10', '203.0.113.22', '198.51.100.7', '192.0.2.55']
  const now = Date.now()
  const rows = []
  for (let i = 0; i < 60; i++) {
    const recent = i < 35 // 前两个 IP 最近 5 分钟内活跃
    const ts = recent ? now - i * 5000 : now - 3600000 - i * 60000
    rows.push({
      ts: new Date(ts).toISOString(),
      client_ip: recent ? ips[i % 2] : ips[2 + (i % 2)],
      qname: ['example.com', 'github.com', 'baidu.com', 'example.org'][i % 4],
      qtype: ['A', 'AAAA', 'A', 'MX'][i % 4],
      rcode: i % 12 === 0 ? 'NXDOMAIN' : 'NOERROR',
      cache_hit: i % 3 !== 0,
      upstream: ['223.5.5.5', '8.8.8.8'][i % 2],
      rtt_ms: 8 + (i % 30),
      via: ['udp', 'dot', 'doh'][i % 3],
    })
  }
  return rows
}

// ---------- 结果收集 ----------
const results = []
function check(name, cond, detail = '') {
  results.push({ name, ok: !!cond })
  console.log(`${cond ? '✅' : '❌'} ${name}${detail ? ' — ' + detail : ''}`)
}

// ---------- 启动 ----------
let browser
try {
  browser = await chromium.launch()
} catch (e) {
  console.error('❌ 无法启动 Chromium。请先执行：npx playwright install chromium')
  console.error('   ' + e.message.split('\n')[0])
  process.exit(2)
}

const page = await browser.newPage({ viewport: { width: 1280, height: 900 } })

// 拦截 /api 请求并返回 mock（登录前设置）
await page.route('**/api/v1/**', (route) => {
  const url = route.request().url()
  const json = (body) => route.fulfill({ json: body })
  if (url.includes('/auth/login')) return json({ access_token: 'mock', refresh_token: 'mock', expires_in: 900, token_type: 'Bearer' })
  if (url.endsWith('/me')) return json({ user: { id: 'u1', username: 'acme-admin', role: 'tenant', tenant_id: 't1' }, tenant: TENANT })
  if (url.includes('/stats/overview')) return json({ qps: 12.5, hit_rate_pct: 88.3, error_rate_pct: 0.4, total_queries: 123456, total_hits: 109000, total_errors: 500, tenant_queries: 8900 })
  if (url.includes('/logs/query')) return json({ total: 60, rows: mockRows() })
  if (url.includes('/endpoints')) return json({
    tenant_id: 't1', prefix: 'acme-01',
    dot_endpoint: 'acme-01.dns.example.com',
    doh_endpoint: 'https://acme-01.dns.example.com/dns-query',
    doq_endpoint: 'quic://acme-01.dns.example.com',
    dot_port: 853, doh_port: 443, doq_port: 853,
    clients: {
      android_private_dns: 'acme-01.dns.example.com',
      ios_profile: 'acme-01.dns.example.com',
      dig_dot: 'dig @acme-01.dns.example.com example.com',
      curl_doh: 'curl https://acme-01.dns.example.com/dns-query',
    },
    nginx_snippet: 'location /api/ { proxy_pass http://127.0.0.1:8080; }',
    caddy_snippet: 'reverse_proxy /api/* 127.0.0.1:8080',
  })
  if (url.includes('/tenants/')) return json(TENANT)
  return json({})
})

// ---------- 1. 登录页 ----------
await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' })
await page.waitForTimeout(600)
const loginText = await page.evaluate(() => document.body.innerText)
check('登录页：品牌标题', loginText.includes('DNSD 客户端门户'))
check(
  '登录页：用户名/密码输入框',
  await page.evaluate(() => !!document.querySelector('input[autocomplete="username"]') && !!document.querySelector('input[autocomplete="current-password"]'))
)
check(
  '登录页：暗色主题背景',
  await page.evaluate(() => getComputedStyle(document.body).backgroundColor === 'rgb(10, 13, 19)')
)
await page.screenshot({ path: join(SHOT_DIR, '01-login.png') })

// ---------- 2. 登录（mock） ----------
await page.fill('input[autocomplete="username"]', 'acme-admin')
await page.fill('input[autocomplete="current-password"]', 'password')
await page.click('button[type="submit"]')
await page.waitForTimeout(1000)

// ---------- 3. Setup ----------
await page.goto(`${BASE}/setup`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1000)
const setupText = await page.evaluate(() => document.body.innerText)
check('Setup：DoT/DoH/DoQ 端点', ['DoT', 'DoH', 'DoQ'].every((t) => setupText.includes(t)))
check('Setup：端点地址', setupText.includes('acme-01.dns.example.com'))
check('Setup：设备配置指南', setupText.includes('Android 私有 DNS'))
await page.screenshot({ path: join(SHOT_DIR, '02-setup.png') })

// ---------- 4. Analytics ----------
await page.goto(`${BASE}/analytics`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1200)
const analytics = await page.evaluate(() => {
  const t = document.body.innerText
  return {
    hasActiveClients: t.includes('活跃客户端'),
    hasOnline: t.includes('使用中'),
    hasOffline: t.includes('离线'),
    onlineMatch: (t.match(/使用中\s*(\d+)/) || [])[1],
    statCards: document.querySelectorAll('.card').length,
  }
})
check('Analytics：活跃客户端板块', analytics.hasActiveClients)
check('Analytics：使用中/离线状态', analytics.hasOnline && analytics.hasOffline)
check('Analytics：在线客户端计数正确', analytics.onlineMatch === '2', `使用中 ${analytics.onlineMatch}`)
check('Analytics：统计卡片渲染', analytics.statCards >= 10, `${analytics.statCards} 卡片`)
await page.screenshot({ path: join(SHOT_DIR, '03-analytics.png'), fullPage: true })

// ---------- 5. Logs ----------
await page.goto(`${BASE}/logs`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1000)
const logsText = await page.evaluate(() => document.body.innerText)
check('Logs：日志表格', logsText.includes('查询日志检索') && logsText.includes('响应码'))
check('Logs：日志行数据', logsText.includes('223.5.5.5') && logsText.includes('example.com'))
await page.screenshot({ path: join(SHOT_DIR, '04-logs.png') })

// ---------- 6. Settings ----------
await page.goto(`${BASE}/settings`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1000)
const settingsText = await page.evaluate(() => document.body.innerText)
check('Settings：协议开关', ['DoT', 'DoH', 'DoQ'].every((t) => settingsText.includes(t)))
check('Settings：DoT 前缀定制', settingsText.includes('DoT 前缀定制'))
check('Settings：修改密码', settingsText.includes('修改密码'))
await page.screenshot({ path: join(SHOT_DIR, '05-settings.png') })

await browser.close()

// ---------- 汇总 ----------
const pass = results.filter((r) => r.ok).length
console.log(`\n========== 渲染自检：${pass}/${results.length} 通过 ==========`)
if (pass < results.length) {
  console.log('失败项：')
  for (const r of results.filter((r) => !r.ok)) console.log('  ❌ ' + r.name)
  process.exit(1)
}
console.log(`截图目录：${SHOT_DIR}`)
