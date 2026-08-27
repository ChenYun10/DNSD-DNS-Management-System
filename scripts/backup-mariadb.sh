#!/bin/bash
# backup-mariadb.sh - MariaDB 每日全量备份(等保: 日志留存/数据备份)
# 用法: backup-mariadb.sh [retention_days]  (默认 30 天)
# cron: 0 2 * * * /opt/dns-platform/scripts/backup-mariadb.sh
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/dns-platform/mariadb}"
RETENTION="${1:-30}"
DB_USER="${DB_USER:-dns_platform}"
DB_PASS="${DB_PASS:-}"
DB_NAME="${DB_NAME:-dns_platform}"
TS=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
OUT="$BACKUP_DIR/${DB_NAME}_${TS}.sql.gz"

if [ -n "$DB_PASS" ]; then
  mysqldump -u"$DB_USER" -p"$DB_PASS" --single-transaction --routines --triggers "$DB_NAME" | gzip > "$OUT"
else
  mysqldump -u"$DB_USER" --single-transaction --routines --triggers "$DB_NAME" | gzip > "$OUT"
fi

# 加密存储(可选): 设置 GPG_KEY 后加密
if [ -n "${GPG_KEY:-}" ]; then
  gpg --batch --yes --recipient "$GPG_KEY" --encrypt "$OUT" && rm -f "$OUT"
fi

# 清理过期
find "$BACKUP_DIR" -name "${DB_NAME}_*.sql.gz*" -mtime +"$RETENTION" -delete

echo "backup ok: $OUT ($(du -h "$OUT" | cut -f1))"
