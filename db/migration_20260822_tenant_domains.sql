-- ============================================================================
-- Migration 2026-08-22: customer custom main domains (客户自定义主域名)
-- Usage: mysql -u root dns_platform < db/migration_20260822_tenant_domains.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_domains (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  domain      VARCHAR(128) NOT NULL UNIQUE,          -- customer's own main domain (apex)
  enabled     TINYINT(1)   NOT NULL DEFAULT 1,
  cert_status ENUM('none','issuing','active','renewing','error') NOT NULL DEFAULT 'none',
  cert_expiry DATETIME(3)  NULL,
  cert_error  VARCHAR(255) NULL,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_td_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  INDEX idx_td_tenant (tenant_id),
  INDEX idx_td_domain (domain)
) ENGINE=InnoDB;
