# dns-platform

**多租户 · 高并发 · 高可用 DNS 云平台 | Multi-tenant · High-performance · Highly-available DNS cloud platform**

[🇨🇳 中文](#-中文) · [🇬🇧 English](#-english)

---

## 🇨🇳 中文

# dns-platform

**多租户 · 高并发 · 高可用 DNS 云平台**

一个完整的 DNS 服务平台:UDP/TCP 传统解析 + **DoT + DoH + DoQ** 四类下行协议、
**多租户 DoT/DoH 前缀定制**、**ECS(EDNS Client Subnet)模拟与传递**、Redis 缓存、
MySQL 查询日志、基于 ECS 的动态预热、上游多协议分流、DNSSEC、**后台自动签发 SSL
(ACME)**、集群化部署与完整的前后端分离管理控制台。

[架构设计](docs/architecture.md) · [安全设计](docs/security.md) ·
[API 参考](docs/api.md) · [集群与性能](docs/cluster.md)

---

## 功能清单

| 模块 | 说明 |
|---|---|
| **下行协议** | UDP / TCP(RFC 1035)、DoT(RFC 7858)、DoH(RFC 8484,GET+POST)、DoQ(RFC 9250) |
| **DoT 前缀定制** | 每租户独立前缀 `gov-acme01.dns.example.com`,SNI 路由租户;未知前缀在 **TLS 握手层直接拒绝**(前缀不可枚举) |
| **ECS 模拟/传递** | 解析客户端 EDNS Client Subnet(RFC 7871),按策略透传上游、回显 scope;**前端可模拟任意子网的完整解析路径**(缓存→分流→上游→DNSSEC) |
| **缓存(Redis+L1)** | 按 `租户×ECS×域名×类型` 粒度缓存,TTL 自适应、负缓存(SOA min)、单飞防击穿;**进程内 L1 热缓存**(64 分片)+ Redis L2,**集群跨实例失效走 pub/sub 广播** |
| **日志(MySQL)** | 全量查询日志异步批量落库(不阻塞请求路径),审计日志只追加;管理端按租户/域名/时间检索 |
| **动态预热** | ①活跃 ECS 自动追踪(Redis Set);②热域名×活跃 ECS 一键预热;③热点临近过期条目自适应异步刷新 |
| **上游分流** | 组/成员 CRUD(udp/tcp/dot/doh/doq),后缀/前缀/精确/正则/全量规则,优先级排序,租户级规则覆盖全局;组内加权轮询/故障切换,健康检查自动剔除故障节点 |
| **上游协议** | 传统 UDP/TCP、DoT、DoH(RFC 8484 POST)、DoQ(RFC 9250 QUIC) |
| **DNSSEC** | `passthrough` / `ad-only` / `verify`(RRSIG 本地校验)三模式;DO 位透传、AD 位策略化 |
| **高并发高可用** | 无状态数据面(多实例水平扩展,Redis 共享缓存);限流(租户/IP,Redis 跨实例);优雅停机;/healthz + /readyz;SO_REUSEPORT 同机多实例 |
| **高价值专用通道** | VIP 租户:专属上游组、独立缓存命名空间、10× 限流、管理通道 mTLS 客户端证书 |
| **后台做 SSL(ACME)** | 客户自定义主域名证书自动签发/续期(HTTP-01;DNS-01 走阿里云支持泛域名),证书落盘后 dnsd 按 SNI 热加载 |
| **前端完整管理** | 控制台完成全部运维:租户全字段编辑、DoT 前缀定制、上游组/成员/规则 CRUD、缓存清理/预热、日志/审计检索、用户与权限、VIP 通道开关 |

## DNS 引擎说明

核心基于 Go 生态事实标准的 `miekg/dns` 协议库自研(完整 RFC 实现),定位是
**多租户转发 + 缓存网关**(BIND/Unbound 不具备多租户前缀/ECS/分流能力)。
递归由上游完成(223.5.5.5/8.8.8.8 等);如需自包含递归,可把 **Unbound 作为上游**
(DoT/DoQ 协议原生支持)或后续增加迭代解析模块。详见 `docs/architecture.md`。

## 架构

```
                    ┌──────────────┐          ┌───────────────┐
   UDP/TCP :53 ────▶│              │          │   frontend    │
   DoT      :853 ──▶│   dnsd       │          │   (SPA)       │
   DoH      :443 ──▶│  (数据面)     │──┐       └──────┬────────┘
   DoQ      :784 ──▶│  无状态      │  │              │ HTTPS/JSON
                    └──────────────┘  │      ┌───────▼────────┐
                                      │      │  apid (REST)   │
                         upstreams    │      │  JWT + RBAC    │
                    (udp/tcp/dot/doh/doq)   └───────┬────────┘
                                      │              │
                    ┌─────────────────▼──┐   ┌───────▼────────┐
                    │ Redis (L2 缓存 /   │   │ MySQL (配置 /  │
                    │  限流 / ECS 跟踪)  │   │  查询日志)     │
                    └────────────────────┘   └────────────────┘
```

集群模式:`haproxy(L4)→ N × dnsd`,共享 Redis/MySQL。详见 [docs/cluster.md](docs/cluster.md)。

## 性能

**缓存命中时热路径零 Redis 往返**:

- **L1 进程内缓存**(64 分片、存打包字节、TTL 上限 60s)置于 Redis 之前
- **限流本地优先**——本地预算耗尽才查 Redis 权威判定
- **ECS 跟踪批量上报**(2s Pipeline),替代每查询 2 次 Redis 写
- **热点域内存化**,替代每查询 1~3 次 SISMEMBER
- SingleFlight 分片、SO_REUSEPORT、/healthz + /readyz

压测:`go run ./tools/dnsbench -server <ip>:53 -qps 10000 -dur 20s`

## 快速开始

### 方式一:Linux 生产部署(systemd 一键脚本)

```bash
sudo bash scripts/install-linux.sh
# 自动完成:Redis+MySQL → 建库 → 交叉编译静态二进制 → systemd 服务 → nginx 前端
# 按脚本末尾提示调用 bootstrap 创建管理员
```

或手动:

```bash
make build-linux        # CGO_ENABLED=0 静态二进制 → bin/linux/(纯 Go,任意 Linux 可跑)
sudo make install       # 安装到 /usr/local/bin + /etc/dns-platform + systemd
# 编辑 /etc/dns-platform/.env(密钥、证书路径、域名)
systemctl enable --now dns-platform-dnsd dns-platform-apid
```

systemd 服务已内置最小权限:专用 `dns` 用户、`CAP_NET_BIND_SERVICE`(免 root 绑 53/853)、
`ProtectSystem`、`NoNewPrivileges`。前端由 nginx 托管静态文件(`deploy/nginx-frontend.conf`)。

### 方式二:Docker Compose(生产推荐)

```bash
cp .env.example .env            # 修改密钥、证书路径、域名
# 准备 *.BASE_DOMAIN 泛域名证书到 certs/
docker compose up -d
# 首次部署:创建管理员(一次性)
curl -X POST http://127.0.0.1:8080/api/v1/bootstrap/admin \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: <BOOTSTRAP_TOKEN>" \
  -d '{"username":"admin","password":"***"}'
```

### 方式三:本地开发(Windows / Linux)

```powershell
# Windows:
.\scripts\start-dev.ps1     # 自动下载 Redis+MySQL、初始化、生成证书
# Linux:
bash scripts/start-dev.sh   # 使用系统 redis/mysql

go run ./cmd/dnsd           # 数据面(开发端口 :5300/853/9443/784,避开本机 53 占用)
go run ./cmd/apid           # 控制面 :8080 / :8443
node frontend/server.js     # 前端 http://127.0.0.1:8081
```

> 本机若已有服务占用 53 端口(如 AdGuard Home),在 `.env` 中把 `DNS_LISTEN_UDP/TCP` 改为空闲端口即可。

### 首次使用流程

1. **bootstrap 管理员**(见上)→ 登录前端(API 地址填 `http://127.0.0.1:8080`)
2. **创建租户**:租户管理 → 新建(名称 + 前缀 + 基域 + VIP 开关)
3. **编辑租户**:租户管理 → 编辑(限流、默认 ECS、协议开关、固定上游组等全字段)
4. **配置上游分流**:上游与分流 → 组 CRUD / 成员 CRUD(udp/tcp/dot/doh/doq)/ 规则 CRUD
5. **定制 DoT 前缀**:租户账号 → DoT/DoH 端点 → 修改前缀 / 启停协议 → 获取部署端点与客户端配置
6. **ECS 模拟验证**:ECS 模拟 → 输入域名 + 子网 → 查看完整解析路径
7. **预热**:缓存与预热 → 添加热域名 → 租户一键预热(自动按活跃 ECS 扩散)

## 冒烟测试结果(本仓库实测)

```
✓ UDP 传统解析         rcode=NOERROR answers=2
✓ DoT(租户前缀 SNI)    rcode=NOERROR answers=2
✓ DoT 未知前缀         TLS 握手层拒绝(租户隔离生效)
✓ DoH POST (RFC8484)   rcode=NOERROR answers=2
✓ DoH GET  (base64url) rcode=NOERROR answers=2
✓ DoQ (RFC9250)        rcode=NOERROR answers=2
✓ ECS 传递 + scope 回显 scope="116.62.52.0/0"
✓ 分流规则 .cn → 国内组 → 223.5.5.5(CNAME 链完整解析)
✓ Redis 缓存命中(二次模拟 0ms 返回)
✓ MySQL 查询日志(23 条 / 5 通道 / 异步批量)
✓ 预热任务(域名×ECS=2 组合,2/2 成功)
✓ 租户全字段编辑 / 上游 DoQ 成员添加(热加载生效)
```

## 集群部署

```bash
cp deploy/cluster/.env.cluster.example .env.cluster
docker compose -f deploy/cluster/docker-compose.cluster.yml --env-file .env.cluster up -d
# haproxy(53/853/443/784/8080)→ dnsd-1 + dnsd-2 + apid + redis + mysql
```

裸机:配合 `deploy/cluster/haproxy.cfg` + `deploy/cluster/dnsd@.service`
(systemd 多实例模板)。完整指南:[docs/cluster.md](docs/cluster.md)。

## 配置参考

所有环境变量见 [.env.example](.env.example)(监听、TLS、缓存、日志、DNSSEC、
限流、ACME、阿里云 DNS-01 等)。

## 文档

- [架构设计](docs/architecture.md) — 请求路径、数据流、扩展性、DNS 引擎选型说明
- [安全设计](docs/security.md) — 威胁模型、控制项、政企专用通道
- [API 参考](docs/api.md) — 全部 REST 端点
- [集群与性能](docs/cluster.md) — 高并发优化、集群部署、扩容发布、限流语义
- [一键部署](DEPLOY.md) — 自定义域名 + TLS 部署脚本说明

## 目录结构

```
cmd/dnsd/        # DNS 数据面(53 / 853 / 443 / 784)
cmd/apid/        # REST 控制面(JWT/RBAC/日志/预热/模拟)
cmd/gencert/     # 自签名泛域名证书生成工具(开发用)
internal/dnsx/   # 核心:监听器 / ECS / 缓存(L1+L2) / 上游 / 分流 / DNSSEC / 预热 / 限流
internal/certmgr/# ACME 签发与续期(lego)
internal/api/    # REST 端点(鉴权、租户、上游、缓存、模拟、日志)
internal/store/  # Redis 缓存 + MySQL 存储 + 异步日志写入器
frontend/        # 管理控制台 SPA(原生 JS,无构建步骤)
deploy/          # Dockerfile ×2 / nginx / systemd / cluster(haproxy+compose)
tools/dnsbench/  # UDP/TCP 压测工具
docs/            # 架构 / 安全 / API / 集群
```

## License

[MIT](LICENSE)。全部依赖均为宽松许可(MIT/BSD/Apache/MPL),无 GPL/AGPL。


---

## 🇬🇧 English

# dns-platform

**Multi-tenant · High-performance · Highly-available DNS cloud platform**

A complete DNS service platform built in Go: traditional UDP/TCP resolution
plus **DoT / DoH / DoQ** encrypted transports, per-tenant DoT/DoH prefix
customization, **ECS (EDNS Client Subnet)** simulation & passthrough, Redis
caching, MySQL query logging, dynamic pre-warming, multi-protocol upstream
split routing, DNSSEC, backend-managed SSL (ACME), cluster deployment and a
full web admin console.

[Architecture](docs/architecture.md) ·
[Security](docs/security.md) · [API](docs/api.md) · [Cluster](docs/cluster.md)

---

## Features

| Area | Highlights |
|---|---|
| **Downstream protocols** | UDP / TCP (RFC 1035), DoT (RFC 7858), DoH (RFC 8484, GET+POST), DoQ (RFC 9250) |
| **Multi-tenancy** | Per-tenant custom DoT prefix via SNI, unknown prefixes rejected at TLS handshake (prefix not enumerable) |
| **ECS** | EDNS Client Subnet (RFC 7871) passthrough, scope echo, and a full ECS simulation path (cache → split → upstream → DNSSEC) |
| **Caching** | Redis L2 + in-process L1 hot cache; per `tenant × ECS × qname × qtype` keying; TTL-adaptive; negative caching (SOA min); cross-instance invalidation via Redis pub/sub |
| **Logging** | Full query log to MySQL, asynchronous batch writer (never blocks the hot path), admin searchable by tenant / domain / time |
| **Dynamic pre-warm** | Active-ECS auto-tracking → one-click tenant warm-up; adaptive refresh of hot entries before expiry |
| **Upstream split** | Groups + members (udp/tcp/dot/doh/doq), suffix/prefix/exact/regex/full rules, priority ordering, health checks with failover |
| **DNSSEC** | `passthrough` / `ad-only` / `verify` (local RRSIG validation), DO-bit passthrough, AD-bit policy |
| **High availability** | Stateless data plane (horizontal scale), graceful shutdown, `/healthz` + `/readyz`, SO_REUSEPORT multi-instance |
| **VIP channel** | Dedicated upstream group, isolated cache namespace, 10× rate-limit multiplier, mTLS admin channel |
| **Admin SSL (ACME)** | Backend-managed certificate issuance & renewal for customer custom main domains (HTTP-01; DNS-01 via Aliyun for wildcards) |
| **Admin console** | Full-featured SPA (vanilla JS, no build step): tenants, upstreams, rules, cache, warmup, logs, users, VIP |

## Architecture

```
                    ┌──────────────┐          ┌───────────────┐
   UDP/TCP :53 ────▶│              │          │   frontend    │
   DoT      :853 ──▶│   dnsd       │          │   (SPA)       │
   DoH      :443 ──▶│  (data plane)│──┐       └──────┬────────┘
   DoQ      :784 ──▶│  无状态      │  │              │ HTTPS/JSON
                    └──────────────┘  │      ┌───────▼────────┐
                                      │      │  apid (REST)   │
                         upstreams    │      │  JWT + RBAC    │
                    (udp/tcp/dot/doh/doq)   └───────┬────────┘
                                      │              │
                    ┌─────────────────▼──┐   ┌───────▼────────┐
                    │ Redis (L2 cache /  │   │ MySQL (config │
                    │  rate limit / ECS) │   │  / logs)      │
                    └────────────────────┘   └────────────────┘
```

Multi-instance deployment: `haproxy (L4) → N × dnsd`, shared Redis/MySQL.
See [docs/cluster.md](docs/cluster.md).

## Performance

The hot path performs **zero Redis round-trips on cache hits**:

- **L1 local cache** (64-shard, packed bytes, TTL-capped 60s) in front of Redis
- **Local-first rate limiting** — Redis consulted only when the local budget is exhausted
- **Batched ECS tracking** (2s pipeline) instead of 2 Redis writes per query
- **In-memory hot-domain set** instead of per-query `SISMEMBER`
- Sharded singleflight, `SO_REUSEPORT`, `/healthz` + `/readyz`

Benchmark: `go run ./tools/dnsbench -server <ip>:53 -qps 10000 -dur 20s`

## Quick Start

### Option 1 — Linux production (systemd, one-click)

```bash
sudo bash scripts/install-linux.sh
# Redis+MySQL → schema → static binaries → systemd services → nginx frontend
# Then create the admin via the bootstrap endpoint (printed at the end)
```

### Option 2 — Docker Compose (recommended for production)

```bash
cp .env.example .env                  # fill in secrets, cert paths, base domain
# prepare a *.BASE_DOMAIN wildcard certificate under certs/
docker compose up -d
curl -X POST http://127.0.0.1:8080/api/v1/bootstrap/admin \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: <BOOTSTRAP_TOKEN>" \
  -d '{"username":"admin","password":"***"}'
```

### Option 3 — Local development

```powershell
# Windows:
.\scripts\start-dev.ps1      # auto-downloads Redis+MySQL, inits schema, generates certs
# Linux:
bash scripts/start-dev.sh

go run ./cmd/dnsd            # data plane (dev ports :5300/853/9443/784)
go run ./cmd/apid            # control plane :8080 / :8443
node frontend/server.js      # console http://127.0.0.1:8081
```

### First-run flow

1. Bootstrap the admin → log in to the console
2. Create a tenant (name + prefix + base domain + VIP toggle)
3. Configure upstream groups / members / split rules
4. Customize the tenant's DoT prefix, enable/disable protocols
5. Verify resolution paths with the ECS simulator
6. Add hot domains and one-click warm-up

## Cluster Deployment

```bash
cp deploy/cluster/.env.cluster.example .env.cluster
docker compose -f deploy/cluster/docker-compose.cluster.yml --env-file .env.cluster up -d
# haproxy (53/853/443/784/8080) → dnsd-1 + dnsd-2 + apid + redis + mysql
```

Bare-metal: `deploy/cluster/haproxy.cfg` + `deploy/cluster/dnsd@.service`
(systemd multi-instance template). Full guide: [docs/cluster.md](docs/cluster.md).

## Configuration

See [.env.example](.env.example) for every environment variable (listeners,
TLS, cache, logging, DNSSEC, rate limits, ACME, Aliyun DNS-01, etc).

## Documentation

- [docs/architecture.md](docs/architecture.md) — request path, data flow, extensibility
- [docs/security.md](docs/security.md) — threat model, controls, VIP channel
- [docs/api.md](docs/api.md) — full REST API reference
- [docs/cluster.md](docs/cluster.md) — high-concurrency tuning & cluster deployment
- [DEPLOY.md](DEPLOY.md) — one-click custom-domain + TLS deployment

## Repository Layout

```
cmd/dnsd/        # DNS data plane (53 / 853 / 443 / 784)
cmd/apid/        # REST control plane (JWT/RBAC/logs/prewarm/simulate)
cmd/gencert/     # self-signed wildcard cert generator (dev)
internal/dnsx/   # core: listeners / ECS / cache(L1+L2) / upstream / split / DNSSEC / warmup / rate limit
internal/certmgr/# ACME issuance & renewal for tenant domains (lego)
internal/api/    # REST handlers (auth, tenants, upstreams, cache, simulate, logs)
internal/store/  # Redis cache + MySQL storage + async query log writer
frontend/        # admin SPA (vanilla JS, no build step)
deploy/          # Dockerfiles, nginx, systemd, cluster (haproxy/compose)
tools/dnsbench/  # UDP/TCP load generator
docs/            # architecture / security / api / cluster
```

## License

[MIT](LICENSE) — all dependencies are permissively licensed (MIT/BSD/Apache/MPL),
no GPL/AGPL.
