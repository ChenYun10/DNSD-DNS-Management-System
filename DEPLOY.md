# dns-platform 部署与运维手册

多租户智能 DNS 云平台：**DoT / DoH / DoQ / 明文 DNS** 四协议 + ECS(EDNS Client Subnet) 就近解析 + Redis 缓存 + MySQL 审计日志 + Web 管理端。

---

## 1. 架构总览

```
                        ┌─────────────────────────────────────────────┐
  客户端                 │  dns-platform 单机部署                       │
  ┌───────┐             │                                             │
  │ 手机/  │──DoT 853──▶│  dnsd (数据面)                               │
  │ 路由器 │──DoH 443──▶│   · 53 UDP/TCP  明文 DNS                    │
  │ 浏览器 │──DoQ 853──▶│   · 443 DoH (RFC 8484)                      │
  │        │──DNS 53───▶│   · 853 DoT (RFC 7858 + dig 兼容双封装)     │
  └───────┘             │   · 853 UDP DoQ (RFC 9250)                  │
                        │   · SNI 前缀 → 租户路由                      │
                        │   · 自动 ECS：客户端源 IP /24 就近解析        │
                        │   · 统计每 5s 推送 Redis                     │
                        ├─────────────────────────────────────────────┤
                        │  apid (控制面, 仅 127.0.0.1:8080)            │
                        │   · REST API + JWT + RBAC                   │
                        │   · 配置热重载信号 → Redis 版本号 → dnsd      │
                        ├─────────────────────────────────────────────┤
                        │  nginx                                          │
                        │   · 8001 TLS  → API 反代                     │
                        │   · 8002 TLS  → 前端 + /api 反代             │
                        │   · 80        前端明文（兼容）                 │
                        ├─────────────────────────────────────────────┤
                        │  Redis(127.0.0.1:6379, 有密码) 缓存/统计/锁  │
                        │  MariaDB(127.0.0.1:3306) 租户/规则/日志       │
                        └─────────────────────────────────────────────┘
```

## 2. 端口一览

| 端口 | 协议 | 用途 | 说明 |
|---|---|---|---|
| 53 | TCP/UDP | 明文 DNS | 外网 UDP 需安全组放行 |
| 443 | TCP | DoH | `https://<domain>/dns-query` |
| 853 | TCP | DoT | RFC 7858；兼容 BIND dig 前缀封装 |
| 853 | UDP | DoQ | RFC 9250 |
| 8001 | TCP/TLS | 管理 API | nginx 反代 → 127.0.0.1:8080 |
| 8002 | TCP/TLS | Web 前端 | 登录管理控制台 |
| 80 | TCP | 前端明文 | 兼容入口 |
| 8080 | TCP | API 原始端口 | **仅 127.0.0.1**，公网不可达 |
| 8443 | TCP | apid 管理通道 | 仅 127.0.0.1 |

## 3. 一键部署

### 3.1 正式证书（推荐，需阿里云 AccessKey）

```bash
sudo bash deploy/deploy.sh \
  -d dns.example.com \
  -e admin@dns.example.com \
  -k <阿里云 AccessKey ID> \
  -s <阿里云 AccessKey Secret> \
  -p '你的初始密码'
```

要求：域名托管在阿里云云解析；AK 权限 `AliyunDNSFullAccess`（RAM 子账号）。

### 3.2 自签名证书（快速体验）

```bash
sudo bash deploy/deploy.sh -d dns.example.com
```

证书自动续期：acme.sh 每日 cron + 季度脚本 `/usr/local/bin/renew-dns-cert.sh`（1/4/7/10 月 1 日 04:00），续期后自动重启 dnsd + reload nginx。

### 3.3 手动部署（分步）

```bash
# 1. 依赖
apt-get install -y redis-server mariadb-server nginx golang-go
# 2. 数据库
mysql -uroot < db/schema.sql
# 3. 编译
make build
# 4. 配置
install -m 0644 .env.example /etc/dns-platform/.env   # 修改 BASE_DOMAIN/密钥
# 5. 安装
make install
# 6. 证书（自签名）
/usr/local/bin/gencert -domain <你的域名> -out /etc/dns-platform/certs
# 7. 启动
systemctl enable --now dns-platform-dnsd dns-platform-apid
```

## 4. 配置项（/etc/dns-platform/.env）

| 变量 | 默认 | 说明 |
|---|---|---|
| `BASE_DOMAIN` | dns.example.com | 主域名；所有租户前缀 = `<prefix>.<BASE_DOMAIN>` |
| `DOT_LISTEN` | :853 | DoT 监听 |
| `DOH_LISTEN` | :443 | DoH 监听（直接对外，无需 nginx） |
| `DOQ_LISTEN` | :853 | DoQ 监听（UDP） |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | certs/ | 通配证书路径（覆盖全部加密 DNS + 8001/8002） |
| `API_LISTEN` | 127.0.0.1:8080 | 管理 API（勿改公网） |
| `API_CORS_ORIGINS` | - | 前端来源白名单 |
| `API_JWT_SECRET` | - | JWT 密钥（安装时随机） |
| `BOOTSTRAP_TOKEN` | - | 首次创建管理员用，一次性 |
| `REDIS_PASSWORD` | - | Redis 密码 |
| `MYSQL_DSN` | dns:***@tcp(127.0.0.1:3306)/dns_platform | MySQL 连接 |
| `ECS_PASSTHROUGH` | true | 客户端无 ECS 时按源 IP 自动合成 /24 |

## 5. 客户端接入

| 场景 | 配置 |
|---|---|
| Android 私人 DNS | 服务器填 `dns.example.com`（或 `gov-acme01.dns.example.com`） |
| DoH | `https://dns.example.com/dns-query` |
| DoT 测试 | `kdig +tls @dns.example.com baidu.com` 或 `dig @dns.example.com +https baidu.com` |
| 租户前缀 | 创建租户后端点 = `xxx.dns.example.com`，需在域名 DNS 加 CNAME → `dns.example.com` |

> ⚠️ BIND 的 `dig +tls` 使用非标长度前缀封装；本平台**双封装兼容**（自动识别），标准客户端（Android/kdig/自研）走 RFC 7858 裸报文，dig 走前缀封装，两者都通。

## 6. 安全加固清单（已内置/建议）

- [x] SSH 密钥登录（`PermitRootLogin prohibit-password`，禁用密码）
- [x] Redis requirepass（仅 127.0.0.1）
- [x] MariaDB 仅 127.0.0.1
- [x] apid 仅 127.0.0.1:8080，公网只能走 8001 TLS
- [x] `.env` 权限 0600，私钥 0600
- [x] nginx `server_tokens off`
- [x] 未知 SNI 前缀在 TLS 层拒绝（防租户枚举）
- [ ] 阿里云安全组：仅放行 22/53/80/443/853/8001/8002（UDP 按需）
- [ ] 启用 ufw 前先 `ufw allow 22`

## 7. 运维排障

**日志**
```bash
journalctl -u dns-platform-dnsd -f        # 数据面
journalctl -u dns-platform-apid -f        # 控制面
tail -f /var/log/cert-renew.log           # 证书续期
```

**统计与健康**
```bash
redis-cli -a <REDIS_PASSWORD> GET dns:stats:overview   # 实时统计
curl -s https://<domain>:8001/api/v1/stats/overview -H "Authorization: Bearer <token>"
```

**常见问题**

| 现象 | 原因/处理 |
|---|---|
| 前端打不开日志 | 强刷(Ctrl+F5)；API 地址填 `https://<domain>:8001`；检查 CORS 白名单 |
| 改分流规则不生效 | 已内置热重载（≤10s）；**注意：租户固定上游组(VIP)优先于分流规则**，想用规则就留空固定组 |
| 命中率低 | 正常现象：一次性域名+短 TTL+客户端自缓存；可用"热域名预热"提升 |
| 上游 UNHEALTHY | 国外 DoT/DoH(8.8.8.8/1.1.1.1) 在国内不可达，改用国内端点（223.5.5.5/doh.360.cn） |
| DoQ 外网不通 | 安全组放行 UDP 853 |
| 忘记 admin 密码 | 登录服务器：生成 bcrypt 后 UPDATE users 表，或联系部署者 |

## 8. API 概览

| 方法/路径 | 说明 |
|---|---|
| POST /api/v1/auth/login | 登录，返回 JWT |
| GET /api/v1/stats/overview | 总览（QPS/命中率/错误率/累计） |
| GET /api/v1/logs/query | 查询日志（qname/qtype/from/to/limit/offset） |
| GET /api/v1/logs/audit | 审计日志 |
| GET/POST /api/v1/groups | 上游组 |
| GET/POST /api/v1/upstreams | 上游成员（udp/tcp/dot/doh/doq） |
| GET/POST /api/v1/rules | 分流规则（suffix/prefix/exact/regex/all） |
| GET/POST /api/v1/tenants | 租户（前缀/协议开关/VIP/默认ECS/固定组） |
| GET/POST /api/v1/users | 用户；PUT /api/v1/users/{id} 改角色/租户/邮箱 |
| POST /api/v1/users/{id}/password | 重置密码 |
| POST /api/v1/reload | 手动触发数据面热重载 |
| POST /api/v1/bootstrap/admin | 首次创建管理员（X-Bootstrap-Token 一次性） |

## 9. 源码结构

```
cmd/dnsd      数据面主程序（监听+统计推送+配置热重载轮询）
cmd/apid      控制面主程序（REST API）
cmd/gencert   自签名通配证书生成器
internal/dnsx 核心：server(四协议监听) / handler(查询流水线) /
               upstream(分组+健康检查+加权) / split(分流) /
               ecs(EDNS 客户端子网) / cache / warmup / ratelimit / dnssec
internal/api  REST 层：auth(JWT+锁定+限流) / handlers_*
internal/store MySQL/Redis 仓储 + 查询日志批量写
internal/model 数据模型
frontend      原生 JS 管理端（零构建，nginx 直出）
db/schema.sql 数据库结构
deploy/       systemd 单元 + nginx 模板
deploy/deploy.sh  一键部署脚本（主域名可配 + TLS）
```
