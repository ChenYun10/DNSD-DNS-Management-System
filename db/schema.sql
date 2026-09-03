-- ============================================================================
-- dns-platform schema (MySQL 8.x / MariaDB 10.6+)
-- 幂等：全部使用 CREATE TABLE IF NOT EXISTS / INSERT ... ON DUPLICATE KEY
-- 应用方式:  mysql -u root -p < db/schema.sql
-- ============================================================================

CREATE DATABASE IF NOT EXISTS dns_platform
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE dns_platform;

-- ---------------------------------------------------------------------------
-- 租户（客户）：每个租户拥有可定制的 DoT/DoH/DoQ 前缀
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id              CHAR(36)     NOT NULL PRIMARY KEY,
  name            VARCHAR(128) NOT NULL,
  prefix          VARCHAR(32)  NOT NULL UNIQUE,          -- 自定义 DoT 前缀（小写字母数字连字符）
  base_domain     VARCHAR(128) NOT NULL,                 -- 例如 dns.example.com
  enabled         TINYINT(1)   NOT NULL DEFAULT 1,
  vip             TINYINT(1)   NOT NULL DEFAULT 0,       -- 政企高价值专用通道
  rate_limit_qps  INT          NOT NULL DEFAULT 100,     -- 每客户端 IP QPS 上限
  cache_max_ttl   INT          NOT NULL DEFAULT 21600,   -- 缓存 TTL 上限（秒）
  default_ecs     VARCHAR(45)  NULL,                     -- 租户默认 ECS（如 203.0.113.0/24）
  allow_ecs       TINYINT(1)   NOT NULL DEFAULT 1,       -- 是否接受客户端 ECS
  dot_enabled     TINYINT(1)   NOT NULL DEFAULT 1,
  doh_enabled     TINYINT(1)   NOT NULL DEFAULT 1,
  doq_enabled     TINYINT(1)   NOT NULL DEFAULT 1,
  upstream_group  VARCHAR(36)  NULL,                     -- 固定上游组（VIP 专用通道）
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  INDEX idx_tenants_base (base_domain)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 用户（平台管理员 / 租户管理员），bcrypt 密码
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id              CHAR(36)     NOT NULL PRIMARY KEY,
  tenant_id       CHAR(36)     NULL,                    -- NULL = 平台管理员
  username        VARCHAR(64)  NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,
  -- 等保三员分立: sysadmin 系统管理 / secadmin 安全管理 / auditadmin 审计管理 / tenant 租户
  role            ENUM('admin','sysadmin','secadmin','auditadmin','tenant') NOT NULL DEFAULT 'tenant',
  email           VARCHAR(128) NULL,
  failed_attempts INT          NOT NULL DEFAULT 0,
  locked_until    DATETIME(3)  NULL,
  last_login      DATETIME(3)  NULL,
  must_change_pwd TINYINT(1)   NOT NULL DEFAULT 0,     -- 首次发放/过期密码强制改密
  pwd_changed_at  DATETIME(3)  NULL,                   -- 密码最近更新时间(定期更换策略)
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 历史密码(等保: 密码不可复用, 防回退)
CREATE TABLE IF NOT EXISTS password_history (
  id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id       CHAR(36)     NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_ph_user (user_id),
  CONSTRAINT fk_ph_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 上游组（分流目标）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS upstream_groups (
  id             CHAR(36)     NOT NULL PRIMARY KEY,
  tenant_id      CHAR(36)     NULL,                     -- NULL = 全局组
  name           VARCHAR(64)  NOT NULL,
  strategy       ENUM('round_robin','weighted','failover') NOT NULL DEFAULT 'weighted',
  health_domain  VARCHAR(128) NULL,                     -- 健康检查探测域名
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_groups_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 上游成员（udp/tcp/dot/doh/doq）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS upstreams (
  id            CHAR(36)      NOT NULL PRIMARY KEY,
  group_id      CHAR(36)      NOT NULL,
  name          VARCHAR(64)   NOT NULL,
  protocol      ENUM('udp','tcp','dot','doh','doq') NOT NULL,
  address       VARCHAR(128)  NOT NULL,                 -- IP 或域名（不含端口）
  port          INT           NOT NULL DEFAULT 53,
  hostname      VARCHAR(128)  NULL,                     -- TLS SNI / DoH Host
  doh_path      VARCHAR(128)  NULL DEFAULT '/dns-query',
  weight        INT           NOT NULL DEFAULT 1,
  timeout_ms    INT           NOT NULL DEFAULT 0,       -- 0 = 使用全局默认
  tls_insecure  TINYINT(1)    NOT NULL DEFAULT 0,       -- 仅允许 dev 环境
  enabled       TINYINT(1)    NOT NULL DEFAULT 1,
  created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_upstreams_group FOREIGN KEY (group_id) REFERENCES upstream_groups(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 分流规则（优先级高的先匹配；租户级规则覆盖全局规则）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS split_rules (
  id          CHAR(36)      NOT NULL PRIMARY KEY,
  tenant_id   CHAR(36)      NULL,                       -- NULL = 全局规则
  name        VARCHAR(64)   NOT NULL,
  match_type  ENUM('suffix','prefix','exact','regex','all') NOT NULL DEFAULT 'suffix',
  match_value VARCHAR(255)  NOT NULL,
  group_id    CHAR(36)      NOT NULL,
  priority    INT           NOT NULL DEFAULT 0,
  enabled     TINYINT(1)    NOT NULL DEFAULT 1,
  created_at  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_rules_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_rules_group  FOREIGN KEY (group_id)   REFERENCES upstream_groups(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 热域名清单（预热数据源）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hot_domains (
  id        CHAR(36)     NOT NULL PRIMARY KEY,
  tenant_id CHAR(36)     NULL,                          -- NULL = 全局
  domain    VARCHAR(128) NOT NULL,
  weight    INT          NOT NULL DEFAULT 1,
  enabled   TINYINT(1)   NOT NULL DEFAULT 1,
  CONSTRAINT fk_hot_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 内网双栈绑定表（IPv6 子网 → 客户端真实 IPv4，用于 ECS 推导与透传）
-- 数据来源：运营商 BRAS / 地址分配系统。IPv4 必须与 IPv6 指向同一物理
-- 归属地/运营商；数据面在 ReloadAll 时读入内存做最长前缀匹配。
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dualstack_bindings (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  ipv6_subnet VARCHAR(45)  NOT NULL,                  -- 如 2001:db8:100::/48
  ipv4        VARCHAR(15)  NOT NULL,                  -- 如 116.62.52.1
  isp         VARCHAR(64)  NULL,                      -- 运营商（可选，仅展示/审计）
  region      VARCHAR(128) NULL,                      -- 归属地（可选）
  enabled     TINYINT(1)   NOT NULL DEFAULT 1,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_dsb_subnet (ipv6_subnet),
  INDEX idx_dsb_ipv4 (ipv4)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 查询日志（高并发写入：异步批量；建议按天分区/归档）
--
-- 索引策略（配合 LOG_QUERY_DEFAULT_WINDOW/LOG_QUERY_MAX_WINDOW 时间窗查询）：
--   * idx_ql_ts (ts)：InnoDB 二级索引末尾隐式含主键 id，即 (ts, id)；
--     可直接支撑「WHERE ts BETWEEN ? AND ? ORDER BY ts DESC, id DESC」的范围
--     扫描（反向扫描），避免全表扫描与 filesort。
--   * idx_ql_tenant_ts (tenant_id, ts)：支撑「租户 × 时间窗」过滤。
--   * 刻意不建 qname 索引：日志检索用 LIKE '%…%'（前置通配），B 树索引无法
--     命中，建了只会放大每次 INSERT 的写放大与磁盘占用（见迁移脚本删除）。
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS query_logs (
  id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts             DATETIME(3)  NOT NULL,
  tenant_id      CHAR(36)     NULL,
  client_ip      VARCHAR(45)  NOT NULL,
  ecs            VARCHAR(45)  NULL,                     -- 使用的 ECS 子网
  qname          VARCHAR(255) NOT NULL,
  qtype          VARCHAR(16)  NOT NULL,
  rcode          VARCHAR(16)  NOT NULL,
  cache_hit      TINYINT(1)   NOT NULL DEFAULT 0,
  upstream_group VARCHAR(64)  NULL,
  upstream       VARCHAR(128) NULL,
  rtt_ms         INT          NOT NULL DEFAULT 0,
  dnssec_ok      TINYINT(1)   NOT NULL DEFAULT 0,
  vip            TINYINT(1)   NOT NULL DEFAULT 0,
  via            VARCHAR(8)   NOT NULL DEFAULT 'udp',   -- udp|tcp|dot|doh|doq|simulate
  INDEX idx_ql_ts (ts),
  INDEX idx_ql_tenant_ts (tenant_id, ts)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 审计日志（管理操作，不可删除/修改——由应用层只写）
-- ---------------------------------------------------------------------------
-- 审计日志(管理操作, 防篡改: 哈希链 prev_hash + entry_hash, 只追加)
CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  actor_id    CHAR(36)     NULL,
  actor_name  VARCHAR(64)  NULL,
  action      VARCHAR(64)  NOT NULL,
  target      VARCHAR(255) NULL,
  detail      JSON         NULL,
  client_ip   VARCHAR(45)  NULL,
  prev_hash   CHAR(64)     NULL,      -- 上一条审计日志的 entry_hash (SHA-256 hex), 首条为 genesis
  entry_hash  CHAR(64)     NULL,      -- 本条日志的 SHA-256(prev_hash|ts|actor|action|target|detail|ip)
  verifier    VARCHAR(64)  NULL,      -- 写入者标识(实例ID/服务名), 便于溯源
  INDEX idx_audit_ts (ts),
  INDEX idx_audit_action (action),
  INDEX idx_audit_hash (entry_hash)
) ENGINE=InnoDB;

-- ============================================================================
-- 种子数据（仅首次部署执行；幂等）
-- ============================================================================

-- 平台管理员不在此处种子创建：请通过带 BOOTSTRAP_TOKEN 的
-- POST /api/v1/bootstrap/admin 一次性创建（见 README 快速开始）。
-- 种子 SQL 仅预置上游组 / 分流规则 / 热域名。

-- 全局默认上游组 + 公共上游（223.5.5.5 阿里 / 119.29.29.29 腾讯 / 1.1.1.1 Cloudflare）
INSERT INTO upstream_groups (id, tenant_id, name, strategy)
SELECT 'aaaaaaaa-0000-0000-0000-000000000001', NULL, 'default', 'weighted'
WHERE NOT EXISTS (SELECT 1 FROM upstream_groups WHERE name = 'default');

INSERT INTO upstream_groups (id, tenant_id, name, strategy)
SELECT 'aaaaaaaa-0000-0000-0000-000000000002', NULL, 'cn-domestic', 'weighted'
WHERE NOT EXISTS (SELECT 1 FROM upstream_groups WHERE name = 'cn-domestic');

INSERT INTO upstream_groups (id, tenant_id, name, strategy)
SELECT 'aaaaaaaa-0000-0000-0000-000000000003', NULL, 'global-vip', 'failover'
WHERE NOT EXISTS (SELECT 1 FROM upstream_groups WHERE name = 'global-vip');

INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'ali-dns', 'udp', '223.5.5.5', 53, '223.5.5.5', NULL, 2, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'ali-dns');

INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'tx-dns', 'udp', '119.29.29.29', 53, '119.29.29.29', NULL, 2, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'tx-dns');

INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000003', 'aaaaaaaa-0000-0000-0000-000000000001', 'cf-doh', 'doh', '1.1.1.1', 443, 'cloudflare-dns.com', '/dns-query', 1, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'cf-doh');

INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000004', 'aaaaaaaa-0000-0000-0000-000000000001', 'google-dot', 'dot', '8.8.8.8', 853, 'dns.google', NULL, 1, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'google-dot');

-- 国内组：阿里 + 腾讯（UDP 传统协议）
INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000005', 'aaaaaaaa-0000-0000-0000-000000000002', 'ali-dns-cn', 'udp', '223.5.5.5', 53, '223.5.5.5', NULL, 2, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'ali-dns-cn');

INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000006', 'aaaaaaaa-0000-0000-0000-000000000002', 'tx-dns-cn', 'udp', '119.29.29.29', 53, '119.29.29.29', NULL, 2, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'tx-dns-cn');

-- VIP 组：DoT(Google) + DoH(Cloudflare) 故障切换
INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, enabled)
SELECT 'bbbbbbbb-0000-0000-0000-000000000007', 'aaaaaaaa-0000-0000-0000-000000000003', 'google-dot-vip', 'dot', '8.8.8.8', 853, 'dns.google', NULL, 1, 1
WHERE NOT EXISTS (SELECT 1 FROM upstreams WHERE name = 'google-dot-vip');

-- 示例分流：.cn 走国内组（优先级 100）
INSERT INTO split_rules (id, tenant_id, name, match_type, match_value, group_id, priority, enabled)
SELECT 'cccccccc-0000-0000-0000-000000000001', NULL, 'cn-suffix', 'suffix', 'cn', 'aaaaaaaa-0000-0000-0000-000000000002', 100, 1
WHERE NOT EXISTS (SELECT 1 FROM split_rules WHERE name = 'cn-suffix');

-- 示例热域名（预热用）
INSERT INTO hot_domains (id, tenant_id, domain, weight, enabled)
SELECT 'dddddddd-0000-0000-0000-000000000001', NULL, 'example.com', 10, 1
WHERE NOT EXISTS (SELECT 1 FROM hot_domains WHERE domain = 'example.com');
