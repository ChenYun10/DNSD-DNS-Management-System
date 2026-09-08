# DNSD 客户端门户（client-web）

DNSD 多租户 DNS 平台的**租户自助门户**，NextDNS 风格暗色 UI。面向租户（tenant 角色）用户：登录后查看自己的 DoT/DoH/DoQ 部署端点、查询日志、分析统计、ECS 模拟诊断，并自助管理协议开关与 DoT 前缀。

技术栈：**Vue 3 + Vite + Tailwind CSS v4**（无其他运行时依赖，图表为自绘 SVG）。

## 与现有 frontend 的区别

| | `frontend/`（管理控制台） | `client-web/`（本目录） |
|---|---|---|
| 目标用户 | 平台管理员（sysadmin 等三员） | 租户客户（tenant） |
| 视角 | 运维：租户/上游/规则/缓存 CRUD | 自助：端点/日志/统计/诊断 |
| 技术栈 | 原生 JS，无构建 | Vue 3 + Vite + Tailwind |

两者共用同一套 `apid` REST API，只是 RBAC 视角不同。

## 目录结构

```
client-web/
├── index.html
├── vite.config.js          # /api 反代到 apid(:8080)
├── package.json
└── src/
    ├── main.js / App.vue / style.css   # 入口 + Tailwind 主题
    ├── router/index.js                 # 路由 + 登录守卫
    ├── store/session.js                # 会话状态（token/用户/租户）
    ├── api/client.js                   # fetch 封装 + JWT + 401 自动续期
    ├── api/auth.js / endpoints.js      # 认证与业务端点
    ├── layout/AppLayout.vue            # 侧边栏 + 顶栏
    ├── components/                     # StatCard/CopyField/Toggle/图表等
    └── views/                          # Setup/Analytics/Logs/Settings/Login
```

## 运行

```bash
# 1. 安装依赖（注意：若 shell 里 NODE_ENV=production，务必加 --include=dev）
unset NODE_ENV && npm install --include=dev

# 2. 开发（端口 8082，/api 自动反代到 http://127.0.0.1:8080）
npm run dev
# 如需指向其他 apid 地址：
#   DNSD_API=http://host:8080 npm run dev

# 3. 生产构建
npm run build          # 产出 dist/
npm run preview        # 本地预览 dist
```

## 渲染自检（无需真实后端）

`scripts/render-check.mjs` 用 playwright 启动真实浏览器，拦截 `/api` 请求返回 mock 数据，验证登录页 + Setup/Analytics/Logs/Settings 五个页面的真实渲染，并截图。

```bash
# 首次需装浏览器（playwright chromium）
npx playwright install chromium

# 另开一个终端跑 dev server，再执行自检
npm run dev
npm run render-check              # 默认 http://localhost:8082
npm run render-check -- http://localhost:9000 /tmp/shots   # 自定义 baseUrl 与截图目录
```

全部通过输出 `N/N 通过` 且退出码为 0；任一失败退出码为 1。截图默认存到系统临时目录 `dnsd-render-check/`。

## 与 apid 对接（端点隐藏）

前端**不暴露后端地址/端点**：所有请求走同源相对路径 `/api`，后端 apid 的真实地址与端口只出现在反向代理配置中，客户端永远看不到。

- **开发**：Vite 将 `/api` 反代到 apid（`DNSD_API` 环境变量可改），规避 CORS。
- **生产**：`dist/` 由 nginx 托管，`location /api/` 反代到内网 apid。见 `deploy/nginx-portal.conf.example`。要求 apid 仅监听内网，并在 apid `.env` 开启 `TRUST_PROXY_HEADERS=true`（否则限流/审计取不到真实客户端 IP）。

> 前端代码里出现的 `/api/v1/...` 路径无法真正隐藏（浏览器总能看到自己发出的请求），隐藏的是**后端地址与端口**——通过反代让客户端只接触一个公开域名。

**控制面内网化不影响 DNS 业务**：apid 是控制面（管理/门户），DNS 解析业务在数据面 dnsd（53/853/443/784），两者独立。apid 设 `API_LISTEN=127.0.0.1:8080` 仅监听回环（`.env.example` 已默认如此），数据面照常监听公网端口，解析不受任何影响。

登录流程：`POST /api/v1/auth/login` → 校验 `must_change_password`（强制改密走受限 token）→ `GET /api/v1/me` 拉取用户+租户 → 进入门户。

## 页面与后端端点

| 页面 | 调用的 API |
|---|---|
| Setup 配置 | `GET /tenants/{id}/endpoints`（端点 + 设备配置 + nginx/caddy 片段） |
| Analytics 分析 | `GET /stats/overview` + `GET /logs/query`（前端聚合）+ `POST /dns/simulate` |
| Logs 日志 | `GET /logs/query?qname&qtype&from&to&limit&offset` |
| Settings 设置 | `GET/PUT /tenants/{id}`、`POST /tenants/{id}/dot`、`POST /auth/change-password` |

## 备注

- 租户 RBAC 与后端一致：租户仅能改自身协议开关与 DoT 前缀；查询日志/统计强制限定本租户。
- 图表数据来自查询日志前端聚合（`limit=500`），受后端 `LogQueryCountCap` 影响。
