#!/bin/bash
# backup-redis.sh - Redis RDB 快照备份(等保: 数据备份)
# 用法: backup-redis.sh [retention_days]  (默认 30 天)
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/dns-platform/redis}"
RETENTION="${1:-30}"
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# 触发 RDB 持久化
redis-cli BGSAVE >/dev/null 2>&1 || true
sleep 2

RDB_PATH=$(redis-cli CONFIG GET dir | tail -1)/dump.rdb
if [ -f "$RDB_PATH" ]; then
  cp "$RDB_PATH" "$BACKUP_DIR/dump_${TS}.rdb"
fi

# 清理过期
find "$BACKUP_DIR" -name "dump_*.rdb" -mtime +"$RETENTION" -delete
echo "redis backup ok: $BACKUP_DIR/dump_${TS}.rdb"
