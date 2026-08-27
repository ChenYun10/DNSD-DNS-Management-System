-- migrate_compliance.sql - 等保改造数据库迁移(在 schema.sql 后执行)
USE dns_platform;

-- 1. users 表: 新角色枚举 + 强制改密字段
ALTER TABLE users
  MODIFY role ENUM('admin','sysadmin','secadmin','auditadmin','tenant') NOT NULL DEFAULT 'tenant',
  ADD COLUMN must_change_pwd TINYINT(1) NOT NULL DEFAULT 0 AFTER last_login,
  ADD COLUMN pwd_changed_at DATETIME(3) NULL AFTER must_change_pwd;

-- 2. password_history 表
CREATE TABLE IF NOT EXISTS password_history (
  id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id       CHAR(36)     NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_ph_user (user_id),
  CONSTRAINT fk_ph_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 3. audit_logs 哈希链字段
ALTER TABLE audit_logs
  ADD COLUMN prev_hash CHAR(64) NULL AFTER client_ip,
  ADD COLUMN entry_hash CHAR(64) NULL AFTER prev_hash,
  ADD COLUMN verifier VARCHAR(64) NULL AFTER entry_hash,
  ADD INDEX idx_audit_hash (entry_hash);

-- 4. 现有 admin 用户兼容: role='admin' 保留(requireRole 兼容为 sysadmin)
--    现有审计日志无哈希, 由应用层首次写入时自动补链(genesis)
-- 5. 现有用户密码入历史(可选, 由应用层首次改密时记录)
