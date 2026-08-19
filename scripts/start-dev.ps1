# PowerShell 开发环境脚本：一键启动 Redis + MySQL(8.0 portable) + 初始化数据库 + 证书 + .env
# 用法： .\scripts\start-dev.ps1
# 说明： 自动下载依赖到 .dev/（首次约 2-3 分钟）；不注册任何系统服务；不占用 53 端口
#        （开发环境 dnsd 使用 5300/853/9443/784，避免与本机既有 DNS 服务冲突）

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$devDir = Join-Path $root ".dev"
New-Item -ItemType Directory -Force -Path $devDir | Out-Null

function Download-File($url, $dest) {
  if (-not (Test-Path $dest)) {
    Write-Host "下载 $url ..." -ForegroundColor Cyan
    curl.exe -sL --retry 3 --max-time 900 -o $dest $url
    if ($LASTEXITCODE -ne 0) { throw "下载失败: $url" }
  }
}

# ---------- Redis (Windows 原生) ----------
$redisDir = Join-Path $devDir "redis"
if (-not (Test-Path (Join-Path $redisDir "redis-server.exe"))) {
  Write-Host "[1/5] 下载 Redis for Windows ..." -ForegroundColor Cyan
  $zip = Join-Path $devDir "redis.zip"
  Download-File "https://github.com/tporadowski/redis/releases/download/v5.0.14.1/Redis-x64-5.0.14.1.zip" $zip
  Expand-Archive -Path $zip -DestinationPath $redisDir -Force
}
if (-not (Get-Process redis-server -ErrorAction SilentlyContinue)) {
  Start-Process -FilePath (Join-Path $redisDir "redis-server.exe") -ArgumentList "--port 6379" -WindowStyle Hidden
  Write-Host "Redis 已启动 :6379" -ForegroundColor Green
} else { Write-Host "Redis 已在运行" -ForegroundColor Green }

# ---------- MySQL 8.0 (portable, 无需安装) ----------
$mysqlDir = Join-Path $devDir "mysql"
if (-not (Test-Path (Join-Path $mysqlDir "bin\mysqld.exe"))) {
  Write-Host "[2/5] 下载 MySQL 8.0 portable ..." -ForegroundColor Cyan
  $zip = Join-Path $devDir "mysql.zip"
  Download-File "https://mirrors.huaweicloud.com/mysql/Downloads/MySQL-8.0/mysql-8.0.24-winx64.zip" $zip
  $tmp = Join-Path $devDir "mysql-src"
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Move-Item (Join-Path $tmp "mysql-8.0.24-winx64") $mysqlDir
}
$dataDir = Join-Path $devDir "mysql-data"
if (-not (Test-Path (Join-Path $dataDir "mysql"))) {
  Write-Host "[3/5] 初始化 MySQL 数据目录 ..." -ForegroundColor Cyan
  & (Join-Path $mysqlDir "bin\mysqld.exe") --initialize-insecure --datadir=$dataDir --basedir=$mysqlDir
}
if (-not (Get-Process mysqld -ErrorAction SilentlyContinue)) {
  Start-Process -FilePath (Join-Path $mysqlDir "bin\mysqld.exe") -ArgumentList "--datadir=$dataDir --port=3306 --bind-address=127.0.0.1 --console" -RedirectStandardError (Join-Path $devDir "mysql.log") -WindowStyle Hidden
  Write-Host "MySQL 已启动 :3306" -ForegroundColor Green
  Start-Sleep 8
} else { Write-Host "MySQL 已在运行" -ForegroundColor Green }

# ---------- 数据库初始化 ----------
Write-Host "[4/5] 初始化数据库 schema ..." -ForegroundColor Cyan
$mysqlCli = Join-Path $mysqlDir "bin\mysql.exe"
& $mysqlCli -h 127.0.0.1 -P 3306 -u root -e "CREATE USER IF NOT EXISTS 'dns'@'%' IDENTIFIED BY 'dns_pass'; GRANT ALL PRIVILEGES ON dns_platform.* TO 'dns'@'%'; FLUSH PRIVILEGES;" 2>$null
$sqlPath = (Join-Path $root "db\schema.sql") -replace '\\','/'
& $mysqlCli -h 127.0.0.1 -P 3306 -u root --default-character-set=utf8mb4 -e "source $sqlPath"
if ($LASTEXITCODE -ne 0) { throw "schema 初始化失败" }
Write-Host "schema OK" -ForegroundColor Green

# ---------- 自签名证书 ----------
if (-not (Test-Path "certs\fullchain.pem")) {
  Write-Host "[5/5] 生成自签名泛域名证书 ..." -ForegroundColor Cyan
  $go = Get-Command go -ErrorAction SilentlyContinue
  if (-not $go) { $go = Get-Command "$env:USERPROFILE\sdk\go\bin\go.exe" -ErrorAction SilentlyContinue }
  if ($go) { & $go.Source run ./cmd/gencert -domain dns.example.com -out certs } else { throw "未找到 go，请先安装 Go 1.26+" }
}

# ---------- .env ----------
if (-not (Test-Path ".env")) {
  Copy-Item .env.example .env
  $secret = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
  $bootstrap = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object {[char]$_})
  $abs = $root -replace '\\','/'
  (Get-Content .env -Raw) `
    -replace 'CHANGE_ME_TO_A_RANDOM_64_HEX_STRING', $secret `
    -replace 'CHANGE_ME_BOOTSTRAP', $bootstrap `
    -replace '\./certs/fullchain\.pem', "$abs/certs/fullchain.pem" `
    -replace '\./certs/privkey\.pem', "$abs/certs/privkey.pem" `
    -replace 'DNS_LISTEN_UDP=:53', 'DNS_LISTEN_UDP=:5300' `
    -replace 'DNS_LISTEN_TCP=:53', 'DNS_LISTEN_TCP=:5300' `
    -replace 'DOH_LISTEN=:8443', 'DOH_LISTEN=:9443' |
    Set-Content .env -Encoding UTF8 -NoNewline
  Write-Host "已生成 .env（随机密钥；BOOTSTRAP_TOKEN 见 .env）" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 环境就绪！启动服务："
Write-Host "   数据面: go run ./cmd/dnsd   (UDP/TCP 5300 · DoT 853 · DoH 9443 · DoQ 784)"
Write-Host "   控制面: go run ./cmd/apid   (API 8080 · 管理通道 8443)"
Write-Host "   前端  : node frontend/server.js  → http://127.0.0.1:8081"
Write-Host "   bootstrap: 读取 .env 的 BOOTSTRAP_TOKEN 后调用 POST /api/v1/bootstrap/admin"
Write-Host "============================================================" -ForegroundColor Yellow
