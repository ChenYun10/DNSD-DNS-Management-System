# dns-platform

**Multi-tenant · High-performance · Highly-available DNS cloud platform**

A complete DNS service platform built in Go: traditional UDP/TCP resolution
plus **DoT / DoH / DoQ** encrypted transports, per-tenant DoT/DoH prefix
customization, **ECS (EDNS Client Subnet)** simulation & passthrough, Redis
caching, MySQL query logging, dynamic pre-warming, multi-protocol upstream
split routing, DNSSEC, backend-managed SSL (ACME), cluster deployment and a
full web admin console.

[中文文档](README.zh-CN.md) · [Architecture](docs/architecture.md) ·
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
