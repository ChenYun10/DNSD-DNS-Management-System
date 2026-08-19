#!/usr/bin/env bash
# ============================================================================
# dns-platform 一键部署脚本
#   支持自定义主域名 + 前端/API TLS(SSL)
#   用法:
#     sudo bash deploy.sh \
#       -d dns.example.com \
#       [-e admin@example.com] \
#       [-k <Aliyun AccessKey ID> -s <Aliyun AccessKey Secret>] \
#       [-p <admin 初始密码>]
#   参数说明:
#     -d  主域名（必填，如 dns.example.com；所有 DNS 端点 = *.主域名 / 主域名）
#     -e  acme 证书邮箱（可选；不填则生成自签名通配证书）
#     -k -s  阿里云 AccessKey（可选；填了则走 DNS-01 申请正式通配证书，
#            域名需托管在阿里云云解析；不填则自签名）
#     -p  web 管理端 admin 初始密码（可选；默认随机生成并打印）
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---------- 参数 ----------
DOMAIN=""
EMAIL=""
ALI_KEY=""
ALI_SECRET=""
ADMIN_PW=""
while getopts "d:e:k:s:p:h" opt; do
  case "$opt" in
    d) DOMAIN="$OPTARG" ;;
    e) EMAIL="$OPTARG" ;;
    k) ALI_KEY="$OPTARG" ;;
    s) ALI_SECRET="$OPTARG" ;;
    p) ADMIN_PW="$OPTARG" ;;
    h) grep '^#' "$0" | head -20; exit 0 ;;
    *) exit 1 ;;
  esac
done

say()  { printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请以 root 运行"
[[ -n "$DOMAIN" ]] || die "必须指定主域名: -d dns.example.com"
echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' || die "域名格式不正确: $DOMAIN"
if [[ -n "$ALI_KEY" || -n "$ALI_SECRET" ]]; then
  [[ -n "$ALI_KEY" && -n "$ALI_SECRET" ]] || die "-k 与 -s 必须同时提供"
fi

# ---------- 1. 依赖 ----------
say "安装依赖 (redis / mariadb / nginx / golang / acme 工具) ..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq redis-server mariadb-server nginx golang-go curl openssl git >/dev/null
else
  die "仅支持 Debian/Ubuntu"
fi
command -v go >/dev/null || die "go 未安装"
systemctl enable --now redis-server 2>/dev/null || true
systemctl enable --now mariadb 2>/dev/null || systemctl enable --now mysql 2>/dev/null || true
systemctl enable --now nginx || true

# ---------- 2. 数据库 ----------
say "初始化数据库 dns_platform ..."
MYSQL=(mysql -uroot)
"${MYSQL[@]}" <<'SQL'
CREATE DATABASE IF NOT EXISTS dns_platform DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'dns'@'localhost' IDENTIFIED BY 'dns_pass';
CREATE USER IF NOT EXISTS 'dns'@'127.0.0.1' IDENTIFIED BY 'dns_pass';
GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'localhost';
GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
"${MYSQL[@]}" dns_platform < db/schema.sql
say "schema 已应用"

# ---------- 3. 编译 ----------
say "编译二进制 (Go $(go version | awk '{print $3}')) ..."
export GOPROXY=https://goproxy.cn,direct
make build

# ---------- 4. 配置目录 + .env ----------
say "生成 /etc/dns-platform/.env ..."
mkdir -p /etc/dns-platform/certs /etc/dns-platform/zones
install -m 0644 .env.example /etc/dns-platform/.env
JWT=$(openssl rand -hex 24)
BT=$(openssl rand -hex 16)
RPW=$(openssl rand -hex 16)
MYSQLP=$(openssl rand -hex 12)
sed -i "s|^BASE_DOMAIN=.*|BASE_DOMAIN=${DOMAIN}|" /etc/dns-platform/.env
sed -i "s|^API_JWT_SECRET=.*|API_JWT_SECRET=${JWT}|" /etc/dns-platform/.env
sed -i "s|^BOOTSTRAP_TOKEN=.*|BOOTSTRAP_TOKEN=${BT}|" /etc/dns-platform/.env
sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${RPW}|" /etc/dns-platform/.env
sed -i "s|^MYSQL_DSN=.*|MYSQL_DSN=dns:${MYSQLP}@tcp(127.0.0.1:3306)/dns_platform?parseTime=true\&charset=utf8mb4|" /etc/dns-platform/.env
# MySQL dns 用户密码同步
mysql -uroot -e "ALTER USER 'dns'@'localhost' IDENTIFIED BY '${MYSQLP}'; ALTER USER 'dns'@'127.0.0.1' IDENTIFIED BY '${MYSQLP}'; FLUSH PRIVILEGES;"
# Redis 密码
if ! grep -q '^requirepass' /etc/redis/redis.conf; then
  echo "requirepass ${RPW}" >> /etc/redis/redis.conf
else
  sed -i "s|^requirepass .*|requirepass ${RPW}|" /etc/redis/redis.conf
fi
systemctl restart redis-server
sed -i "s|^API_CORS_ORIGINS=.*|API_CORS_ORIGINS=https://${DOMAIN}:8002,https://${DOMAIN}:8001,http://${DOMAIN},http://127.0.0.1:8081|" /etc/dns-platform/.env
cp /etc/dns-platform/.env "$ROOT/.env"

# ---------- 5. 证书 ----------
say "签发证书 (*.${DOMAIN} + ${DOMAIN}) ..."
if [[ -n "$ALI_KEY" ]]; then
  # 正式通配证书（阿里云 DNS-01）
  if [ ! -f /root/.acme.sh/acme.sh ]; then
    cd /tmp && rm -rf acme.sh
    git clone --depth 1 https://gitee.com/neilpang/acme.sh.git >/dev/null 2>&1
    cd acme.sh && ./acme.sh --install -m "${EMAIL:-admin@${DOMAIN}}" >/dev/null 2>&1
  fi
  export Ali_Key="$ALI_KEY" Ali_Secret="$ALI_SECRET"
  /root/.acme.sh/acme.sh --issue --dns dns_ali -d "$DOMAIN" -d "*.$DOMAIN" --server letsencrypt --force >/dev/null 2>&1 \
    || die "acme 签发失败，请检查 AK 权限（需 AliyunDNSFullAccess）"
  /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" -d "*.$DOMAIN" --ecc \
    --key-file /etc/dns-platform/certs/privkey.pem \
    --fullchain-file /etc/dns-platform/certs/fullchain.pem \
    --reloadcmd "systemctl restart dns-platform-dnsd && systemctl reload nginx" >/dev/null 2>&1
  say "正式通配证书已签发（acme.sh 自动续期）"
else
  # 自签名通配证书（生产建议改用正式证书）
  ./bin/gencert -domain "$DOMAIN" -out /etc/dns-platform/certs
  say "自签名通配证书已生成（如需正式证书请提供阿里云 AK 重新执行）"
fi
chown -R dns:dns /etc/dns-platform 2>/dev/null || true

# ---------- 6. systemd ----------
say "安装 systemd 服务 ..."
useradd -r -s /usr/sbin/nologin dns 2>/dev/null || true
install -m 0755 bin/dnsd /usr/local/bin/dnsd
install -m 0755 bin/apid /usr/local/bin/apid
install -m 0755 bin/gencert /usr/local/bin/gencert
install -m 0644 deploy/dnsd.service /etc/systemd/system/dns-platform-dnsd.service
install -m 0644 deploy/apid.service /etc/systemd/system/dns-platform-apid.service
chown -R dns:dns /etc/dns-platform
systemctl daemon-reload
systemctl enable --now dns-platform-dnsd dns-platform-apid
sleep 2

# ---------- 7. nginx (API 8001 TLS / 前端 8002 TLS / 80 明文) ----------
say "配置 nginx (8001 API TLS / 8002 前端 TLS / 80) ..."
cat > /etc/nginx/sites-enabled/dns-platform <<NGINXEOF
server {
    listen 8001 ssl;
    http2 on;
    server_name _;
    ssl_certificate /etc/dns-platform/certs/fullchain.pem;
    ssl_certificate_key /etc/dns-platform/certs/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }
}

server {
    listen 8002 ssl;
    http2 on;
    server_name _;
    root $ROOT/frontend;
    index index.html;
    ssl_certificate /etc/dns-platform/certs/fullchain.pem;
    ssl_certificate_key /etc/dns-platform/certs/privkey.pem;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src *; frame-ancestors 'none'" always;

    gzip on;
    gzip_types text/css application/javascript application/json;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}

server {
    listen 80 default_server;
    server_name _;
    root $ROOT/frontend;
    index index.html;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src *; frame-ancestors 'none'" always;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 30s;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINXEOF
nginx -t >/dev/null 2>&1 || die "nginx 配置错误"
systemctl reload nginx
# 确保 80/443/853/8001/8002 不被其他配置占用
rm -f /etc/nginx/sites-enabled/default
systemctl reload nginx

# ---------- 8. 初始化租户/管理员 ----------
say "初始化平台 (租户默认 + 管理员) ..."
sleep 2
API=http://127.0.0.1:8080
# 默认租户（前缀 = 主域名第一段，如 cn）
PREFIX="${DOMAIN%%.*}"
TENANT_ID=$(mysql -uroot -N dns_platform -e "SELECT id FROM tenants WHERE prefix='${PREFIX}' LIMIT 1;")
if [[ -z "$TENANT_ID" ]]; then
  TENANT_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
  mysql -uroot dns_platform -e "INSERT INTO tenants (id, name, prefix, base_domain, enabled, vip, rate_limit_qps, cache_max_ttl, allow_ecs, dot_enabled, doh_enabled, doq_enabled) VALUES ('${TENANT_ID}', '${PREFIX}', '${PREFIX}', '${DOMAIN}', 1, 1, 200, 10800, 1, 1, 1, 1);"
fi
if [[ -z "$ADMIN_PW" ]]; then
  ADMIN_PW="Admin@$(openssl rand -hex 4 | tr 'a-f' 'A-F')a1"
fi
curl -s -X POST "$API/api/v1/bootstrap/admin" -H 'Content-Type: application/json' \
  -H "X-Bootstrap-Token: $BT" \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}" >/dev/null 2>&1 || true

# ---------- 9. 完成 ----------
say "完成 ✅"
echo
echo "====================== 部署信息 ======================"
echo "  主域名           : ${DOMAIN}"
echo "  前端 (TLS)       : https://${DOMAIN}:8002"
echo "  API  (TLS)       : https://${DOMAIN}:8001"
echo "  DoH              : https://${DOMAIN}/dns-query  (TCP 443)"
echo "  DoT              : ${DOMAIN}:853 (TCP)"
echo "  DoQ              : ${DOMAIN}:853 (UDP)"
echo "  明文 DNS         : ${DOMAIN}:53 (UDP/TCP)"
echo "  管理员           : admin / ${ADMIN_PW}"
echo "  租户前缀示例     : xxx.${DOMAIN} → 租户 xxx"
echo "  证书             : /etc/dns-platform/certs/"
echo "  配置文件         : /etc/dns-platform/.env"
echo "====================================================="
echo "提示: 1) 阿里云安全组需放行 53/443/853(TCP+UDP)/8001/8002;"
echo "     2) 管理员登录后请立即修改密码;"
echo "     3) 部署后执行: systemctl status dns-platform-dnsd dns-platform-apid"
