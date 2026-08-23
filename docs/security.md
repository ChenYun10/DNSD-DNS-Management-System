# 安全设计

目标：**为安全而生**，并为政企客户提供**高价值专用通道**。

## 1. 威胁模型

| 威胁 | 缓解 |
|---|---|
| 前缀枚举/暴力接入 | 未知 SNI 前缀在 TLS 握手层拒绝（alert internal_error），握手即失败，无 DNS 报文可探测 |
| 未授权管理访问 | JWT(15min) + 一次性 Refresh Token(Redis)；RBAC 角色隔离；管理通道独立端口 + 可选 mTLS |
| 密码爆破 | bcrypt(12)；连续 5 次失败锁定 15 分钟；登录接口按 IP 限速（Redis） |
| DNS 反射/放大 | 限流（租户×IP）；响应不小于查询的放大控制（EDNS 4096 上限） |
| 缓存投毒/污染 | 缓存 key 值域白名单过滤（防 Redis key 注入）；仅缓存已验证来源的上游应答；TTL 上限 |
| SQL 注入 | 全部参数化查询（database/sql `?` 绑定），无动态拼接 |
| XSS（控制台） | 前端所有动态内容经 escapeHtml 转义；CSP 头；无 eval |
| 跨域越权 | CORS 严格白名单（无 `*`）；服务端 scopeTenant 强制租户边界 |
| 敏感数据泄露 | .env 不提交；密钥环境变量注入；审计日志不含密码/令牌 |
| DoS | QPS 限流、body 大小上限、查询长度校验、并发单飞、上游超时+熔断 |

## 2. 传输安全

- TLS 1.2+（禁用 1.0/1.1），强密码套件白名单（AES-GCM / CHACHA20-POLY1305）
- DoT/DoH/DoQ 共用泛域名证书 `*.BASE_DOMAIN`（生产用正式 CA / 内网用私有 CA）
- HSTS、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、CSP 等安全响应头
- 管理通道 `API_ADMIN_LISTEN`（独立端口）可通过 `API_MTLS_CA_FILE` 启用**客户端证书双向认证**

## 3. 认证与授权（RBAC）

- **admin**：平台级，可管理全部租户/上游/规则/用户/缓存/日志
- **tenant**：仅自有租户资源；服务端 `scopeTenant` 中间件强制校验
  （前端隐藏不等于授权，后端必须二次校验）
- JWT：HS256、`sub`/`role`/`tid`/`jti`、15 分钟过期；刷新令牌 Redis 存储、单次使用、
  登出即吊销（黑名单 + 删除 refresh）
- 租户用户只能查询**自己租户**的日志与指标（`queryLogs` 强制覆盖 tenant_id）

## 4. 数据安全

- 密码：bcrypt cost=12，永不落明文/日志
- Redis：生产建议启用 ACL 与 TLS（redis.conf 侧配置）；key 前缀按业务隔离
- MySQL：最小权限账号（仅 dns_platform 库）；审计日志应用层只追加
- 密钥管理：全部经环境变量注入；`API_JWT_SECRET` 建议 64 位随机 hex；启动时校验长度

## 5. 政企高价值专用通道（VIP）

VIP 租户（`tenants.vip=1`）自动获得：

1. **专用上游组**：`upstream_group` 固定路由（如 `global-vip`），不与其他租户争抢资源，
   健康检查/故障切换独立
2. **独立缓存命名空间**：`dns:cache:{tenant}:…` 前缀隔离，无跨租户缓存串扰
3. **高限流配额**：`RATE_LIMIT_VIP_MULT`（默认 10×）
4. **专属管理通道**：管理员通过 mTLS 管理端口（:8443）运维，客户流量与管理流量物理分离
5. **预热优先**：租户级热域名 × 活跃 ECS 一键预热，保障专线客户首查体验

## 6. 运维基线

- 生产环境强制：`ENV=prod` 时禁止 memory 缓存与 stdout 日志（配置校验拒绝启动）
- 上游 `tls_insecure=true` 仅允许 dev 环境（prod 直接拒绝）
- 定期轮换：JWT 密钥、bootstrap token（bootstrap 完成后删除该环境变量）、MySQL 口令
- 监控：`/healthz`（存活）、`/readyz`（Redis 连通）、`/api/v1/stats/overview`（QPS/命中率）
- 审计巡检：`audit_logs` 记录登录/失败/管理动作，配合 SIEM 接入

## 7. 已知边界（诚实声明）

- DNSSEC `ad-only` 模式信任上游验证（推荐配置为 8.8.8.8/1.1.1.1 等验证型解析器）；
  `verify` 模式做 RRSIG 本地校验，但完整信任链验证建议依赖验证型上游
- DoH 客户端真实 IP 依赖同机 nginx 设置的 `X-Real-IP`（部署模板已配置，注意勿暴露 API 直连）
- Redis/MySQL 本身的访问控制（ACL/TLS/防火墙）属于部署基线，见部署文档
