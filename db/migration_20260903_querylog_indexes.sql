-- ============================================================================
-- 迁移：query_logs 索引优化（降低写入放大与查询 I/O）
-- 日期：2026-09-03
-- 应用方式：mysql -u root -p dns_platform < db/migration_20260903_querylog_indexes.sql
-- 幂等：可重复执行（DROP 前先判断索引是否存在）
-- ============================================================================

USE dns_platform;

-- 1) 删除 idx_ql_qname：日志检索使用 LIKE '%…%'（前置通配），B 树索引无法命中；
--    该索引在百万级高并发写入下只带来显著的写放大与磁盘占用，无查询收益。
SET @idx_exists := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'query_logs'
    AND index_name = 'idx_ql_qname'
);
SET @ddl := IF(@idx_exists > 0,
  'ALTER TABLE query_logs DROP INDEX idx_ql_qname',
  'SELECT ''idx_ql_qname already absent'' AS note');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2)（可选）若确有大量等值/前缀域名检索需求，再按需加前缀索引；否则保持精简。
--    时间范围查询已由 idx_ql_ts / idx_ql_tenant_ts 覆盖，无需新增。
