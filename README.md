# DNS 云平台（多租户 · 高并发 · 高可用）

一个**完整的 DNS 服务端平台**：UDP/TCP 传统解析 + DoT + DoH + DoQ 四类下行协议，
多租户 **DoT/DoH 前缀定制**、**ECS（EDNS Client Subnet）模拟与传递**、**Redis 缓存**、
**MySQL 查询日志**、**基于 ECS 的动态预热**、**上游多协议分流**（DoH/DoT/DoQ/传统）、
**DNSSEC**、前后端隔离的管理控制台与**政企高价值专用通道**（VIP/mTLS）。

> **DNS 引擎说明**：核心基于 Go 生态事实标准的 `miekg/dns` 协议库自研（完整 RFC 实现），
> 定位是**多租户转发/缓存网关**（BIND/Unbound 不具备多租户前缀/ECS/分流能力）。
> 递归由上游完成（223.5.5.5/8.8.8.8 等）；如需自包含递归，可把 **Unbound 作为上游**
> （DoT/DoQ 协议原生支持）或后续增加迭代解析模块。详见 `docs/architecture.md`。

```
┌──────────────┐    HTTPS/JSON    ┌───────────────────┐
│  前端 SPA    │ ───────────────► │  apid (REST API)  │  :8080 客户 API
│  :8081       │                  │  JWT + RBAC       │  :8443 管理通道(mTLS可选)
└──────────────┘                  └────────┬──────────┘
                                           │ 数据面零依赖
┌──────────────┐   UDP/TCP:53              ▼
│  客户端      │ ──────────────────► ┌───────────────────┐
│  DoT 853     │ ───(SNI租户路由)──► │  dnsd (DNS核心)   │──► 上游组(分流/健康检查/故障切换)
│  DoH 443     │ ───(Host租户路由)──► │  ECS/缓存/DNSSEC │──► UDP/TCP/DoT/DoH/DoQ
│  DoQ 784     │ ──────────────────► └───┬───────┬───────┘
└──────────────┘                          │       │
                                     Redis(缓存)  MySQL(日志/元数据)
```

## 功能清单

| 模块 | 说明 |
|---|---|
| **下行协议** | UDP / TCP（RFC 1035）、DoT（RFC 7858）、DoH（RFC 8484，GET+POST）、DoQ（RFC 9250） |
| **DoT 前缀定制** | 每租户独立前缀 `gov-acme01.dns.example.com`，SNI 路由租户；未知前缀在 **TLS 握手层直接拒绝**（前缀不可枚举） |
| **ECS 模拟/传递** | 解析客户端 EDNS Client Subnet（RFC 7871），按策略透传上游、回显 scope；**前端可模拟任意子网的完整解析路径**（缓存→分流→上游→DNSSEC） |
| **缓存（Redis）** | 按 `租户×ECS×域名×类型` 粒度缓存，TTL 自适应、负缓存（SOA min）、单飞防击穿、跨实例共享 |
| **日志（MySQL）** | 全量查询日志异步批量落库（不阻塞请求路径），审计日志只追加；管理端可按租户/域名/时间检索 |
| **动态预热** | ① 活跃 ECS 自动追踪（Redis Set）；② 热域名 × 活跃 ECS 一键预热；③ 热点近过期条目自适应异步刷新 |
| **上游分流** | 后缀/前缀/精确/正则/全量规则，优先级排序，租户级规则覆盖全局；组内加权/轮询/故障切换；健康检查自动摘除故障节点 |
| **上游协议** | 传统 UDP/TCP、DoT、DoH（RFC 8484 POST）、DoQ（RFC 9250 QUIC） |
| **DNSSEC** | `passthrough` / `ad-only` / `verify`（RRSIG 本地校验）三模式；DO 位透传、AD 位策略化 |
| **高并发高可用** | 无状态数据面（多实例水平扩展，Redis 共享缓存）；限流（租户×IP，Redis 跨实例）；优雅停机；/healthz + /readyz |
| **高价值专用通道** | VIP 租户：专属上游组、独立缓存命名空间、10× 限流、管理通道 mTLS 客户端证书 |
| **前端完整管理** | 控制台可完成全部运维：租户全字段编辑、DoT 前缀定制、上游组/成员/规则 CRUD、缓存清理/预热、日志/审计检索、用户与权限、VIP 通道开关 |

## 目录结构

```
dns-platform/
├── cmd/
│   ├── dnsd/          # DNS 数据面守护进程（53/853/443/784）
│   ├── apid/          # REST 控制面（JWT/RBAC/日志/预热/模拟）
│   └── gencert/       # 自签名泛域名证书生成工具（开发用）
├── internal/
│   ├── config/        # 环境变量配置 + .env 加载 + 校验
│   ├── model/         # 领域模型（租户/上游/规则/日志）
│   ├── store/         # Redis 缓存 + MySQL 仓储 + 异步日志写入器
│   ├── dnsx/          # DNS 核心：监听器/ECS/缓存/上游/分流/DNSSEC/预热/限流/指标
│   └── api/           # REST API：认证/RBAC/租户/上游/缓存/模拟/日志
├── frontend/          # 管理控制台 SPA（原生 JS，无构建步骤）
├── db/schema.sql      # MySQL schema + 种子数据（幂等）
├── deploy/            # Dockerfile ×2 / nginx / systemd 单元
├── scripts/           # start-dev.ps1 / start-dev.sh / install-linux.sh
├── Makefile           # 构建 / 交叉编译 / 安装
└── docs/              # 架构 / 安全 / API 文档
```

## 快速开始

### 方式一：Linux 生产部署（systemd 一键脚本）

```bash
sudo bash scripts/install-linux.sh
# 自动完成：Redis+MySQL → 建库 → 交叉编译静态二进制 → systemd 服务 → nginx 前端
# 按脚本末尾提示调用 bootstrap 创建管理员
```

或手动：

```bash
make build-linux        # CGO_ENABLED=0 静态二进制 → bin/linux/（纯 Go，任意 Linux 可跑）
sudo make install       # 安装到 /usr/local/bin + /etc/dns-platform + systemd
# 编辑 /etc/dns-platform/.env（密钥、证书路径、域名）
systemctl enable --now dns-platform-dnsd dns-platform-apid
```

systemd 服务已内置最小权限：专用 `dns` 用户、`CAP_NET_BIND_SERVICE`（免 root 绑 53/853）、
`ProtectSystem`、`NoNewPrivileges`。前端由 nginx 托管静态文件（`deploy/nginx-frontend.conf`）。

### 方式二：Docker Compose（生产推荐）

```bash
cp .env.example .env            # 修改密钥、证书路径、域名
# 准备 *.BASE_DOMAIN 泛域名证书到 certs/
docker compose up -d
# 首次部署：创建管理员（一次性）
curl -X POST http://127.0.0.1:8080/api/v1/bootstrap/admin \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: <BOOTSTRAP_TOKEN>" \
  -d '{"username":"admin","password":"***"}'
```

### 方式三：本地开发（Windows / Linux）

```powershell
# Windows:
.\scripts\start-dev.ps1     # 自动下载 Redis+MySQL、初始化、生成证书
# Linux:
bash scripts/start-dev.sh   # 使用系统 redis/mysql

go run ./cmd/dnsd           # 数据面（开发端口 :5300/853/9443/784，避开本机 53 占用）
go run ./cmd/apid           # 控制面 :8080 / :8443
node frontend/server.js     # 前端 http://127.0.0.1:8081
```

> 本机若已有服务占用 53 端口（如 AdGuard Home），在 `.env` 中把 `DNS_LISTEN_UDP/TCP` 改为空闲端口即可。

### 首次使用流程

1. **bootstrap 管理员**（见上）→ 登录前端（API 地址填 `http://127.0.0.1:8080`）
2. **创建租户**：租户管理 → 新建（名称 + 前缀 + 基域 + VIP 开关）
3. **编辑租户**：租户管理 → 编辑（限流、默认 ECS、协议开关、固定上游组等全字段）
4. **配置上游分流**：上游与分流 → 组 CRUD / 成员 CRUD（udp/tcp/dot/doh/doq）/ 规则 CRUD
5. **定制 DoT 前缀**：租户账号 → DoT/DoH 端点 → 修改前缀 / 启停协议 → 获取部署端点与客户端配置
6. **ECS 模拟验证**：ECS 模拟 → 输入域名 + 子网 → 查看完整解析路径
7. **预热**：缓存与预热 → 添加热域名 → 租户一键预热（自动按活跃 ECS 扩散）

## 冒烟测试结果（本仓库实测）

```
✓ UDP 传统解析         rcode=NOERROR answers=2
✓ DoT(租户前缀 SNI)    rcode=NOERROR answers=2
✓ DoT 未知前缀         TLS 握手层拒绝（租户隔离生效）
✓ DoH POST (RFC8484)   rcode=NOERROR answers=2
✓ DoH GET  (base64url) rcode=NOERROR answers=2
✓ DoQ (RFC9250)        rcode=NOERROR answers=2
✓ ECS 传递 + scope 回显 scope="116.62.52.0/0"
✓ 分流规则 .cn → 国内组 → 223.5.5.5（CNAME 链完整解析）
✓ Redis 缓存命中（二次模拟 0ms 返回）
✓ MySQL 查询日志（23 条 / 5 通道 / 异步批量）
✓ 预热任务（域名×ECS=2 组合，2/2 成功）
✓ 租户全字段编辑 / 上游 DoQ 成员添加（热加载生效）
```

## 文档

- [架构设计](docs/architecture.md) — 请求路径、数据流、扩展性、DNS 引擎选型说明
- [安全设计](docs/security.md) — 威胁模型、控制项、政企专用通道
- [API 参考](docs/api.md) — 全部 REST 端点
- [配置参考](.env.example) — 环境变量说明

## License

内部项目 / 保留所有权利。
