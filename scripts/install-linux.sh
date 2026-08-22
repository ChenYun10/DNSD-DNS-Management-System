#!/usr/bin/env bash
# ============================================================================
# dns-platform Linux 一键部署脚本（Ubuntu/Debian/RHEL/CentOS）
# 用法:  sudo bash scripts/install-linux.sh
# 步骤:  安装 Redis+MySQL → 建库 → 交叉编译二进制 → systemd 服务 → 初始化管理员
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

say()  { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请以 root 运行: sudo bash scripts/install-linux.sh"

# ---------- 1. 依赖 ----------
if command -v apt-get >/dev/null; then
  say "安装依赖 (apt) ..."
  apt-get update -qq
  apt-get install -y -qq redis-server mysql-server nginx golang-go ca-certificates 2>/dev/null || \
  apt-get install -y -qq redis-server mysql-server nginx ca-certificates
elif command -v yum >/dev/null; then
  say "安装依赖 (yum) ..."
  yum install -y redis mysql-server nginx golang ca-certificates
else
  die "不支持的包管理器（请手动安装 redis/mysql/nginx/go 后重试）"
fi

# ---------- 2. Redis / MySQL 服务 ----------
systemctl enable --now redis-server redis 2>/dev/null || systemctl enable --now redis
systemctl enable --now mysql mysqld mariadb 2>/dev/null || true

# ---------- 3. 数据库 ----------
say "初始化数据库 ..."
MYSQLP=$(openssl rand -hex 12)
MYSQL=(mysql -uroot)
if ! "${MYSQL[@]}" -e "SELECT 1" >/dev/null 2>&1; then
  # 部分发行版 root 用 auth_socket
  MYSQL=(mysql -uroot)
fi
"${MYSQL[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS dns_platform DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'dns'@'localhost' IDENTIFIED BY '${MYSQLP}';
CREATE USER IF NOT EXISTS 'dns'@'127.0.0.1' IDENTIFIED BY '${MYSQLP}';
GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'localhost';
GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
"${MYSQL[@]}" -e "ALTER USER 'dns'@'localhost' IDENTIFIED BY '${MYSQLP}'; ALTER USER 'dns'@'127.0.0.1' IDENTIFIED BY '${MYSQLP}'; FLUSH PRIVILEGES;" >/dev/null 2>&1 || true
"${MYSQL[@]}" dns_platform < db/schema.sql
say "schema 已应用"

# ---------- 4. 编译 ----------
command -v go >/dev/null || die "未找到 go，请先安装 Go 1.26+"
say "交叉编译 Linux amd64 静态二进制 ..."
make build-linux

# ---------- 5. 安装 ----------
say "安装二进制与 systemd 服务 ..."
useradd -r -s /usr/sbin/nologin dns 2>/dev/null || true
make install

# ---------- 5b. 随机化平台密钥(JWT/BOOTSTRAP/REDIS/MYSQL) ----------
say "随机化平台密钥 (JWT / BOOTSTRAP / REDIS / MYSQL) ..."
JWT=$(openssl rand -hex 24)
BT=$(openssl rand -hex 16)
RPW=$(openssl rand -hex 16)
sed -i "s|^API_JWT_SECRET=.*|API_JWT_SECRET=${JWT}|" /etc/dns-platform/.env
sed -i "s|^BOOTSTRAP_TOKEN=.*|BOOTSTRAP_TOKEN=${BT}|" /etc/dns-platform/.env
sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${RPW}|" /etc/dns-platform/.env
sed -i "s|^MYSQL_DSN=.*|MYSQL_DSN=dns:${MYSQLP}@tcp(127.0.0.1:3306)/dns_platform?parseTime=true\&charset=utf8mb4|" /etc/dns-platform/.env
mysql -uroot -e "ALTER USER 'dns'@'localhost' IDENTIFIED BY '${MYSQLP}'; ALTER USER 'dns'@'127.0.0.1' IDENTIFIED BY '${MYSQLP}'; FLUSH PRIVILEGES;" 2>/dev/null || true
if ! grep -q '^requirepass' /etc/redis/redis.conf 2>/dev/null; then
  echo "requirepass ${RPW}" >> /etc/redis/redis.conf
else
  sed -i "s|^requirepass .*|requirepass ${RPW}|" /etc/redis/redis.conf
fi
systemctl restart redis-server 2>/dev/null || systemctl restart redis 2>/dev/null || true
chmod 0600 /etc/dns-platform/.env

# ---------- 6. 证书（无证书则生成自签名，生产请替换） ----------
if [ ! -f /etc/dns-platform/certs/fullchain.pem ]; then
  say "生成自签名泛域名证书（生产请替换为正式 CA 证书）..."
  BASE_DOMAIN=$(grep -E '^BASE_DOMAIN=' /etc/dns-platform/.env | cut -d= -f2 || echo dns.example.com)
  /usr/local/bin/gencert -domain "$BASE_DOMAIN" -out /etc/dns-platform/certs
fi
chown -R dns:dns /etc/dns-platform

# ---------- 7. 启动 ----------
say "启动服务 ..."
systemctl daemon-reload
systemctl enable --now dns-platform-dnsd dns-platform-apid
systemctl restart nginx

# ---------- 8. 前端（nginx 托管） ----------
if [ -d frontend ] && ! grep -q dns-platform /etc/nginx/conf.d/default.conf 2>/dev/null; then
  sed "s|/var/www/dns-platform/frontend|$ROOT/frontend|g" deploy/nginx-frontend.conf > /etc/nginx/conf.d/dns-platform.conf
  systemctl reload nginx
fi

# ---------- 9. 管理员引导 ----------
API=${API_URL:-http://127.0.0.1:8080}
BT=$(grep -E '^BOOTSTRAP_TOKEN=' /etc/dns-platform/.env | cut -d= -f2)
ADMIN_PW="Admin@$(openssl rand -hex 4 | tr 'a-f' 'A-F')a1"
say "创建管理员 (admin) ..."
curl -s -X POST "$API/api/v1/bootstrap/admin" -H 'Content-Type: application/json' \
  -H "X-Bootstrap-Token: $BT" \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}" >/dev/null 2>&1 || true
say "服务已就绪："
echo "  DNS 数据面 : UDP/TCP 53 · DoT 853 · DoH 443(nginx) · DoQ 784"
echo "  API        : $API  (管理通道 127.0.0.1:8443)"
echo "  前端       : http://<本机IP>/"
echo "  管理员     : admin / ${ADMIN_PW}  (登录后请立即修改)"
echo "  全部凭据   : /etc/dns-platform/credentials.txt (0600)"
# 凭据汇总(0600)
cat > /etc/dns-platform/credentials.txt <<EOF
[dns-platform credentials - $(date -Is)]
管理员          : admin / ${ADMIN_PW}
MySQL dns 用户  : dns / ${MYSQLP}
Redis           : requirepass ${RPW}
API JWT_SECRET  : ${JWT}
BOOTSTRAP_TOKEN : ${BT}
配置文件        : /etc/dns-platform/.env
EOF
chmod 0600 /etc/dns-platform/credentials.txt
chown dns:dns /etc/dns-platform/credentials.txt
say "完成 ✅"
