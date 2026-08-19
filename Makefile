# DNS 云平台 Makefile（Linux 构建/测试/部署）
# 用法: make build-linux && sudo make install

GO      ?= go
BINDIR  ?= bin
PREFIX  ?= /usr/local
CONFDIR ?= /etc/dns-platform
SYSDIR  ?= /etc/systemd/system

.PHONY: all build build-linux test vet fmt install uninstall clean

all: build

build: ## 本机构建
	$(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/dnsd ./cmd/dnsd
	$(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/apid ./cmd/apid
	$(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/gencert ./cmd/gencert

build-linux: ## Linux amd64 交叉构建（纯 Go，CGO 关闭，静态二进制）
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/linux/dnsd ./cmd/dnsd
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/linux/apid ./cmd/apid
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BINDIR)/linux/gencert ./cmd/gencert

test: ## 单元测试
	$(GO) test ./...

vet: ## 静态检查
	$(GO) vet ./...

fmt: ## 格式化
	gofmt -w cmd internal

install: ## 安装到系统（systemd + 配置目录）
	install -d $(PREFIX)/bin
	install -m 0755 $(BINDIR)/linux/dnsd $(PREFIX)/bin/dnsd
	install -m 0755 $(BINDIR)/linux/apid $(PREFIX)/bin/apid
	install -m 0755 $(BINDIR)/linux/gencert $(PREFIX)/bin/gencert
	install -d $(CONFDIR)
	@if [ ! -f $(CONFDIR)/.env ]; then \
	  install -m 0640 .env.example $(CONFDIR)/.env; \
	  echo "==> 已安装配置模板 $(CONFDIR)/.env，请填写密钥/证书路径"; \
	fi
	install -m 0644 deploy/dnsd.service $(SYSDIR)/dns-platform-dnsd.service
	install -m 0644 deploy/apid.service $(SYSDIR)/dns-platform-apid.service
	install -d $(CONFDIR)/certs
	systemctl daemon-reload
	@echo "==> 完成。编辑 $(CONFDIR)/.env 后: systemctl enable --now dns-platform-dnsd dns-platform-apid"

uninstall:
	systemctl disable --now dns-platform-dnsd dns-platform-apid 2>/dev/null || true
	rm -f $(SYSDIR)/dns-platform-dnsd.service $(SYSDIR)/dns-platform-apid.service
	rm -f $(PREFIX)/bin/dnsd $(PREFIX)/bin/apid $(PREFIX)/bin/gencert
	systemctl daemon-reload

clean:
	rm -rf $(BINDIR)
