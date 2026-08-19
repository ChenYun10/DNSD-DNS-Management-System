# 架构设计

## 1. 总体拓扑

```
                        ┌──────────────────────────────────────────────┐
                        │                控制面 (apid :8080/:8443)      │
  前端 SPA (静态, :8081) │  JWT/RBAC · 租户/前缀 · 上游分流配置 · 预热   │
        │ HTTPS/JSON    │  ECS 模拟 · 日志查询 · 审计 · 指标            │
        ▼               └──────────────┬───────────────────────────────┘
                                       │ 配置热加载 (ReloadAll)
┌──────────────┐    UDP/TCP :53        ▼
│    客户端     │ ───────────────► ┌──────────────────────────────────┐
│  DoT :853    │ ──SNI 前缀路由──► │       数据面 (dnsd)              │
│  DoH :443    │ ──Host 前缀路由──►│ 解析管线（见 §2）                │
│  DoQ :784    │ ─────────────────►│ 无状态 · 多实例水平扩展           │
└──────────────┘                   └──────┬───────────────┬───────────┘
                                          │               │
                                     Redis(缓存/限流/ECS)   MySQL(仅元数据读取+异步日志)
```

**核心原则：数据面与控制面隔离。**
DNS 请求路径（dnsd）只访问 Redis；MySQL 仅在启动/配置变更时读取元数据（租户、上游、
规则），且热路径全部经 Redis 缓存。查询日志由异步批量写入器落 MySQL，请求线程零阻塞。

## 2. 解析管线（每条查询）

```
客户端请求
  │
  ├─ 1. 传输层：UDP/TCP(53) · DoT(853, SNI→租户) · DoH(443, Host→租户) · DoQ(784)
  ├─ 2. 协议校验：QNAME 长度/标签数上限；EDNS 版本 !=0 → BADVERS
  ├─ 3. 租户解析：SNI/Host 前缀 → Redis 缓存租户 → 无前缀用默认租户
  ├─ 4. 限流：租户×客户端IP 滑动窗口（Redis INCR+EXPIRE）；VIP 10× 配额；超限 REFUSED+EDE
  ├─ 5. ECS：解析 EDNS0_SUBNET；租户策略（allow_ecs / default_ecs）；记录活跃 ECS
  ├─ 6. 缓存查询：key = dns:cache:{租户}:{ECS|g}:{qname}:{qtype}（Redis）
  │       命中 → TTL 衰减调整 → 返回；热点近过期 → 触发自适应预热
  ├─ 7. 单飞（singleflight）：同 key 并发查询合并为一次上游请求（防击穿）
  ├─ 8. 分流：VIP 固定组 > 分流规则（优先级降序，租户规则优先）> 默认组
  ├─ 9. 上游故障切换：加权/轮询/故障优先选择；健康检查标记摘除；UDP 截断自动走 TCP
  ├─ 10. DNSSEC：DO 位透传；ad-only 采纳上游 AD；verify 模式本地 RRSIG 校验
  ├─ 11. 缓存回写：TTL=min(记录TTL, 租户上限)；负缓存用 SOA minimum；NXDOMAIN 30s 上限
  ├─ 12. 响应：剥离上游 ECS、回显 scope、压缩
  └─ 13. 异步日志：QueryLogRow → 内存队列 → 批量 INSERT(500/2s) → MySQL
```

## 3. 多租户 DoT/DoH/DoQ 前缀

- 租户表 `tenants.prefix` 存自定义前缀（如 `gov-acme01`），完整端点为
  `gov-acme01.dns.example.com`。
- DoT：TLS `GetConfigForClient` 从 SNI 提取前缀 → Redis 查租户 → 未启用/未知前缀
  返回错误使 **TLS 握手失败**，外部无法枚举有效前缀。
- DoH：从 HTTP Host 头提取前缀；DoQ：TLS ALPN `doq` + SNI。
- 每个租户独立：缓存命名空间（key 前缀）、限流配额、上游组（VIP 固定组）、
  ECS 策略（允许客户端自定义 / 强制默认子网）、协议开关。

## 4. ECS（EDNS Client Subnet）

| 能力 | 实现 |
|---|---|
| 解析 | `ecsFromMsg`：提取 Family/Source/Address，掩码归一化 |
| 传递 | `attachECS`：克隆查询注入 ECS 后发往上游（上游支持则生效） |
| 缓存作用域 | 缓存 key 含 ECS 子网 → 不同子网不同缓存条目（GeoDNS 正确性） |
| scope 回显 | RFC 7871 §7.2.2：响应附加 EDNS0_SUBNET（scope） |
| 模拟 | `POST /api/v1/dns/simulate`：携带模拟 ECS 走完整管线，返回缓存/分流/上游/耗时全链路 trace |
| 预热 | 活跃 ECS 记录到 Redis Set（7 天 TTL）→ 预热任务按 活跃ECS×热域名 扩散 |

## 5. 缓存设计（Redis）

- **key**：`dns:cache:{tenant}:{ecs}:{qname}:{qtype}`，qname 小写、值域白名单过滤（防注入）
- **value**：`{m: base64(packed msg), at: 存储时间, ttl: 秒}`，Redis 自身 TTL 同步
- **命中**：按 `ttl - (now - at)` 衰减应答 TTL，保持缓存语义正确
- **单飞**：进程内 per-key flight 合并并发；跨实例由 Redis 共享缓存兜底
- **预热**：`dns:hot:{tenant}` Set 存热域名；`dns:ecs:{tenant}` Set 存活跃子网
- **速率**：`dns:rate:{tenant}:{ip}:{second}` INCR+EXPIRE(2s)

## 6. 上游与分流

- 组（`upstream_groups`）：策略 `weighted | round_robin | failover`，可选健康探测域名
- 成员（`upstreams`）：协议 `udp|tcp|dot|doh|doq`，地址/端口/SNI/权重/超时
- 规则（`split_rules`）：`suffix|prefix|exact|regex|all` × 优先级 × 租户作用域
- 健康检查：每 30s 探测 `HEALTH_DOMAIN`，连续 3 次失败摘除，恢复后自动回归
- 故障切换：组内按策略选节点；超时/网络错误尝试下一个；全部失败 → SERVFAIL
- UDP 截断：收到 TC 置位响应 → 同节点 TCP 重试

## 7. 日志与指标

- **查询日志**：内存 channel(8192) + 批量 INSERT（500 条或 2s），MySQL 故障时丢弃最旧并计数，
  服务不降级；`query_logs` 建议按天分区归档
- **审计日志**：所有管理动作（登录/租户/前缀/上游/预热/清理）只追加写入 `audit_logs`
- **指标**：进程内 60s 滚动窗口（QPS/命中率/错误率）+ 累计值 + 按上游/租户计数，
  `GET /api/v1/stats/overview` 输出

## 8. 高可用与扩展

- dnsd 无状态 → 多实例 + 负载均衡（DNS anycast/LB）水平扩展，Redis 共享缓存
- apid 无状态 → 多实例，JWT/Refresh/限流状态在 Redis
- 优雅停机：SIGTERM → 停止监听 → 排空连接（10s 窗口）
- 探活：`/healthz`（进程）与 `/readyz`（缓存连通性）
- MySQL 故障：数据面继续服务（元数据有 Redis 缓存，日志有丢弃保护）

## 9. 配置热加载

管理端任何写操作（组/成员/规则/热域名/租户）自动触发 `ReloadAll`：
groups/upstreams/tenants/rules/hot 列表 → 重建运行时视图（无需重启、无请求中断）。
