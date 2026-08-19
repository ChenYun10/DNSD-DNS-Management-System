# REST API 参考

Base URL：`http://<host>:8080`（管理通道 `:8443`，可选 mTLS）
认证：`Authorization: Bearer <access_token>`（登录/刷新获取，15 分钟过期，自动续期由前端处理）

## 公共端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/healthz` | 存活探针 |
| GET | `/api/v1/readyz` | 就绪探针（含 Redis 连通性） |
| GET | `/api/v1/system/info` | 平台信息（base_domain/dnssec_mode/features） |
| POST | `/api/v1/auth/login` | `{username,password}` → `{access_token,refresh_token}` |
| POST | `/api/v1/auth/refresh` | `{refresh_token}` → 新令牌对（单次使用） |
| POST | `/api/v1/bootstrap/admin` | 首次创建管理员（需 `X-Bootstrap-Token`，一次性） |

## 认证端点（Bearer）

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| POST | `/api/v1/auth/logout` | 任意 | 吊销当前令牌 |
| GET | `/api/v1/me` | 任意 | 当前用户 + 所属租户 |

## 租户（DoT/DoH 前缀定制）

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/api/v1/tenants` | admin | 租户列表 |
| POST | `/api/v1/tenants` | admin | 创建租户（name/prefix/base_domain/vip/…） |
| GET/PUT/DELETE | `/api/v1/tenants/{id}` | admin / 所属租户 | 租户详情/更新/删除 |
| POST | `/api/v1/tenants/{id}/dot` | admin / 所属租户 | **DoT 前缀定制**：`{prefix, dot_enabled, doh_enabled, doq_enabled}` |
| GET | `/api/v1/tenants/{id}/endpoints` | admin / 所属租户 | 部署端点 + 客户端配置 + nginx/caddy 片段 |
| POST | `/api/v1/tenants/{id}/warm` | admin / 所属租户 | 一键预热该租户热域名 × 活跃 ECS |
| GET | `/api/v1/tenants/{id}/stats` | admin / 所属租户 | 租户查询计数 |

## 用户（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/users` | 用户列表 |
| POST | `/api/v1/users` | 创建用户（role: admin/tenant） |
| POST | `/api/v1/users/{id}/password` | 重置密码（≥12 位） |
| DELETE | `/api/v1/users/{id}` | 删除用户（不可自删） |

## 上游与分流（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/groups` | 组 + 成员 + 健康状态 |
| POST/PUT/DELETE | `/api/v1/groups[/{id}]` | 组 CRUD（strategy: weighted/round_robin/failover） |
| POST/PUT/DELETE | `/api/v1/upstreams[/{id}]` | 上游成员 CRUD（protocol: udp/tcp/dot/doh/doq） |
| GET | `/api/v1/rules` | 分流规则 |
| POST/PUT/DELETE | `/api/v1/rules[/{id}]` | 规则 CRUD（suffix/prefix/exact/regex/all） |
| POST | `/api/v1/reload` | 手动热加载数据面 |

> 所有配置写操作自动触发数据面热加载，无需重启。

## 缓存与预热（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/cache/stats` | 驱动/活跃ECS/DNSSEC计数/日志批量统计 |
| POST | `/api/v1/cache/purge` | `{tenant_id?, qname?, ecs?}` 精确/范围清理 |
| POST | `/api/v1/cache/warm` | `{tenant_id, domains[], ecs[]?}` 启动预热任务（ECS 缺省=活跃集合） |
| GET | `/api/v1/cache/warm-jobs` | 预热任务列表/进度 |

## ECS 模拟（登录用户）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/dns/simulate` | `{qname, qtype, ecs?, tenant_id?, flush?}` → 完整解析 trace（缓存命中/上游组/上游节点/RTT/DNSSEC/应答），租户用户强制限定自有租户 |

## 日志（MySQL）

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/api/v1/logs/query` | admin/tenant | 分页查询日志；`tenant_id` 对租户用户强制覆盖；支持 qname/qtype/from/to/limit/offset |
| GET | `/api/v1/logs/audit` | admin | 最近审计日志（200 条） |

## 指标

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/api/v1/stats/overview` | 任意 | QPS/命中率/错误率/累计 |
| GET | `/api/v1/stats/upstreams` | admin | 上游查询分布 + 健康状态 |

## 热域名（admin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/hot-domains` | 列表 |
| POST | `/api/v1/hot-domains` | `{domain, weight, enabled}` 添加 |
| DELETE | `/api/v1/hot-domains/{id}` | 删除 |

## 错误格式

```json
{ "error": "描述信息" }
```

常见状态码：`400` 参数错误 / `401` 未认证或令牌失效 / `403` 越权 / `404` 不存在 /
`409` 冲突（前缀占用）/ `429` 限流 / `423` 账号锁定 / `500` 内部错误。
