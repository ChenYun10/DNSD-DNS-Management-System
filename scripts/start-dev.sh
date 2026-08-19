#!/usr/bin/env bash
# dns-platform Linux 开发环境脚本（无需 root，纯本地进程）
# 依赖: redis-server / mysql(或 mariadb) / go 1.26+ / node
# 用法:  bash scripts/start-dev.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

say() { printf '\033[1;36m[dev]\033[0m %s\n' "$*"; }

# ---------- Redis ----------
if ! command -v redis-server >/dev/null; then say "未找到 redis-server，跳过（请安装）"; else
  if ! pgrep -x redis-server >/dev/null; then
    redis-server --port 6379 --daemonize yes
    say "Redis 已启动 :6379"
  else
    say "Redis 已在运行"
  fi
fi

# ---------- MySQL ----------
MYSQLD="$(command -v mysqld || command -v mariadbd || true)"
if [ -z "$MYSQLD" ]; then say "未找到 mysqld/mariadbd，跳过（请安装）"; else
  if ! pgrep -f 'mysqld|mariadbd' >/dev/null; then
    if [ -d .dev/mysql-data ]; then
      "$MYSQLD" --datadir="$ROOT/.dev/mysql-data" --port=3306 --bind-address=127.0.0.1 >.dev/mysql.log 2>&1 &
      sleep 5
      say "MySQL 已启动 :3306"
    else
      say "未初始化数据目录，请先运行: mkdir -p .dev/mysql-data && mysqld --initialize-insecure --datadir=.dev/mysql-data"
    fi
  else
    say "MySQL 已在运行"
  fi
fi

# ---------- schema ----------
MYSQL="$(command -v mysql || command -v mariadb || true)"
if [ -n "$MYSQL" ]; then
  "$MYSQL" -h127.0.0.1 -uroot -e "CREATE DATABASE IF NOT EXISTS dns_platform DEFAULT CHARACTER SET utf8mb4;" 2>/dev/null || true
  "$MYSQL" -h127.0.0.1 -uroot dns_platform < db/schema.sql 2>/dev/null || say "schema 应用失败（root 密码？）"
  "$MYSQL" -h127.0.0.1 -uroot -e "CREATE USER IF NOT EXISTS 'dns'@'localhost' IDENTIFIED BY 'dns_pass'; GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null || true
fi

# ---------- 证书 ----------
if [ ! -f certs/fullchain.pem ]; then
  say "生成自签名证书 ..."
  go run ./cmd/gencert -domain dns.example.com -out certs
fi

# ---------- .env ----------
if [ ! -f .env ]; then
  sed -e 's|\./certs/fullchain\.pem|'"$ROOT"'/certs/fullchain.pem|' \
      -e 's|\./certs/privkey\.pem|'"$ROOT"'/certs/privkey.pem|' \
      -e 's|DNS_LISTEN_UDP=:53|DNS_LISTEN_UDP=:5300|' \
      -e 's|DNS_LISTEN_TCP=:53|DNS_LISTEN_TCP=:5300|' \
      -e 's|DOH_LISTEN=:8443|DOH_LISTEN=:9443|' \
      .env.example > .env
  SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  BOOT=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  sed -i "s/CHANGE_ME_TO_A_RANDOM_64_HEX_STRING/$SECRET/; s/CHANGE_ME_BOOTSTRAP/$BOOT/" .env
  say "已生成 .env（BOOTSTRAP_TOKEN=$BOOT）"
fi

say ""
say "============================================================"
say " 数据面: go run ./cmd/dnsd   (UDP/TCP 5300 · DoT 853 · DoH 9443 · DoQ 784)"
say " 控制面: go run ./cmd/apid   (API 8080 · 管理通道 8443)"
say " 前端  : node frontend/server.js  → http://127.0.0.1:8081"
say " 管理   : 读取 .env 的 BOOTSTRAP_TOKEN 后调用 POST /api/v1/bootstrap/admin"
say "============================================================"
