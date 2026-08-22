# 高并发优化 & 集群化部署

## 一、架构总览

```
                     ┌──────────────┐
   客户端 (UDP 53)──▶│              │
   客户端 (TCP 53)──▶│   haproxy    │──▶ dnsd-1 (inst-1) ─┐
   客户端 (DoT 853)─▶│   (L4 LB)    │──▶ dnsd-2 (inst-2) ─┤ 共享 Redis(缓存/限流)
   客户端 (DoH 443)─▶│              │──▶ dnsd-3 (inst-3) ─┤ 共享 MySQL(配置/日志)
   客户端 (DoQ 784)─▶└──────────────┘                      └── apid(控制面,经 LB :8080)
```

- **数据面无状态**:dnsd 实例之间零通信,状态全在 Redis/MySQL → 横向扩容就是加实例
- **控制面单点可再扩**:apid 的有状态部分(证书/账号)在 MySQL,多实例+前端 nginx 即可

## 二、本次高并发优化(相对旧版热路径)

旧版**每条查询 2~6 次 Redis 往返**:限流 INCR、缓存 GET、命中后再 GET 查 TTL、
`TrackActiveECS` 每查询 SADD+EXPIRE、`isHotDomain` 每查询 1~3 次 SISMEMBER。
DNS 应答本来该 <1ms,全耗在网络 RTT 上。本次改造:

| 优化 | 做法 | 效果 |
|---|---|---|
| **L1 本地缓存** | 64 分片进程内缓存,存打包字节(无 base64/JSON),TTL 上限 60s | 缓存命中零 Redis 往返 |
| **集群缓存一致性** | Redis pub/sub `dns:l1:invalidate` 通道,任一实例/控制面 purge 立即广播,各节点清本地 L1 | purge 秒级生效;兜底 L1 TTL 60s |
| **ECS 跟踪批量** | `TrackActiveECS` 改为非阻塞 channel + 2s 批量 Pipeline(SADD+EXPIRE 合并) | 每查询 2 次 Redis → 约每 2s 1 次 |
| **热点集内存化** | `isHotDomain` 从 Redis SISMEMBER 改为 Core 内存 map(ReloadAll 时加载) | 命中路径再省 1~3 次往返 |
| **TTL 复用** | 缓存 Get 直接返回剩余 TTL,自适应预热不再二次读 Redis | 省 1 次往返 |
| **限流本地优先** | 每实例 1s 窗口内存计数;本地预算耗尽才查 Redis 权威判定 | 正常流量零 Redis;超限流量仍全局限 |
| **SingleFlight 分片** | 全局锁 → 64 分片 | 高并发下不同 key 不互锁 |
| **SO_REUSEPORT** | UDP/TCP listener 开启(miekg/dns ReusePort) | 同机多实例可同时绑 53/853/443/784,内核级收包分流 |
| **健康检查端点** | DoH 增加 `/healthz`(存活)+ `/readyz`(Redis 连通) | LB 探活依据 |
| **自适应预热限流** | 预热 goroutine 用信号量(32)限并发,饱和时跳过 | 防止热点批量过期时 goroutine 风暴 |

**预期收益**:缓存命中率高的场景(热点域名/ECS 少的部署),单实例 QPS 从 Redis
RTT 瓶颈(约 5~20k)提升到纯 CPU 瓶颈(数十万级);延迟从"2×RTT"降到纯本地。

> 注意:L1 是本进程私有,TCP/UDP/DoT/DoH/DoQ 共享;多实例间依赖 TTL 上限
> (60s)+ pub/sub 失效保证一致性,写多读少场景请调小 `L1_MAX_TTL`(编译期常量,
> 见 `internal/dnsx/l1cache.go`)。

## 三、集群部署

### 方式 A:docker compose(最快验证)

```bash
cd dns-platform
cp deploy/cluster/.env.cluster.example .env.cluster   # 填真实密码/密钥
docker compose -f deploy/cluster/docker-compose.cluster.yml --env-file .env.cluster up -d
```

- 拓扑:redis + mysql + apid + dnsd-1/dnsd-2 + haproxy(53/853/443/784/8080)
- 证书目录 `deploy/cluster/certs/` 所有实例共享,先放入通配符证书
  (`fullchain.pem` + `privkey.pem`);客户域证书由 apid 签发后同步到该目录

### 方式 B:裸机 systemd 多实例

```bash
# 每台机编译部署(或从 CI 分发)
CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/dnsd ./cmd/dnsd
CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/apid ./cmd/apid

# 实例 env(每实例一份,INSTANCE_ID 不同)
cp .env.example /etc/dns-platform/dnsd-1.env
sed -i 's/INSTANCE_ID=.*/INSTANCE_ID=inst-1/' /etc/dns-platform/dnsd-1.env

cp deploy/cluster/dnsd@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dnsd@1 dnsd@2      # 同机双实例(SO_REUSEPORT)
```

### 方式 C:跨机(生产推荐)

1. 每台机 1~N 个 dnsd(SO_REUSEPORT 支持同机多实例)
2. 前端放 haproxy 2.4+(`deploy/cluster/haproxy.cfg`,后端 IP 改成实际节点):
   - `53 udp/tcp`、`853 tcp`、`443 tcp`(DoH TLS 透传)、`784 udp`(DoQ)
   - TCP 后端 `check` 每 5s 探活;UDP 后端靠客户端重试兜底
3. 高可用 LB 本身:keepalived VIP 或云厂商 SLB(UDP/TCP 四层转发)
4. 证书分发:通配符证书放共享卷;客户域证书在 apid 签发后
   `rsync -a /var/lib/dns-platform/certs/ node2:/var/lib/dns-platform/certs/`
   (dnsd 每 60s 重扫证书目录,无需重启)

## 四、配置同步与一致性

| 数据 | 存放 | 同步机制 |
|---|---|---|
| 租户/上游/分流规则/热点域 | MySQL | dnsd 每 10s 轮询 `dns:config:version`,变更即 ReloadAll |
| DNS 应答缓存 | Redis(L2)+ 进程内(L1) | L1 靠 TTL 上限 + pub/sub 失效广播 |
| 限流计数 | 本地窗口 + Redis 权威 | 超限流量才打 Redis |
| ECS 活跃集 | Redis Set | 批量 2s 上报 |
| 证书 | 共享目录/rsync | dnsd 每 60s 重扫 |
| 查询日志 | MySQL(异步批量) | dnsd 直写(LOG_DRIVER=mysql)或经 apid |

## 五、扩容/发布流程

**扩容**:新节点部署 dnsd → haproxy 加 server → reload(无损,`kill -USR1` 或
`haproxy -c` 后重启)。

**发布(滚动)**:haproxy 摘除节点 → `systemctl stop dnsd@n`(优雅停机,10s 窗口
等 in-flight)→ 换二进制 → 启动 → 探活通过后加回 LB。

**回滚**:保留上一版二进制,重复上述流程。

## 六、监控与压测

- **健康**:`https://<node>:443/healthz`(存活)、`/readyz`(Redis 连通,503 表示
  缓存故障应摘除);控制面 `/api/v1/healthz`、`/api/v1/readyz`
- **指标**:dnsd 每 5s 推送 `dns:stats:overview` 到 Redis(实例维度 QPS/命中率/
  错误率),apid 的 overview 接口聚合展示
- **压测**:`tools/dnsbench`(UDP/TCP):
  ```bash
  bin/dnsbench -server <LB_IP>:53 -qps 50000 -dur 20s -threads 8 -qname www.baidu.com
  ```
  ⚠️ 对生产压测会触发限流/告警,先小 qps 试,或在对端临时调大 RATE_LIMIT_QPS。

## 七、限流语义(集群)

- 每个实例维护自己的 1s 窗口(本地优先),**正常流量零 Redis**
- 本地预算耗尽 → Redis INCR 权威判定 → 全局限流生效
- 效果:单 IP 实际上限 ≈ 实例数 × RATE_LIMIT_QPS(每实例预算);如需严格全局
  单 IP 上限,把 RATE_LIMIT_QPS 按实例数下调,或后续改成 Redis 固定窗口+本地
  令牌桶混合模式

## 八、已知边界

- DoQ 端口用 784(AdGuard 事实标准),非 RFC 9250 默认端口;对外服务建议
  域名解析走 853(UDP)/8853,或保留 784 并在文档标注
- L1 缓存 TTL 上限 60s:purge 广播不可达时(Redis 抖动),最坏 60s 内旧答案
  可能被读到
- haproxy UDP 健康检查需自定义 DNS 探测报文(配置里已给示例),默认不开启
