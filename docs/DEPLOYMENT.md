# Hy2-Gateway 部署指南

## 前置条件

- 一台有公网 IP 的服务器（Gateway）
- 一台或多台 Node 服务器（已部署 hysteria2 server + WARP 出口）
- 一个域名（用于 TLS 证书，也可以用自签证书 + insecure 模式）
- Go 1.22+（编译用，部署机器不需要）

## 1. 编译

```bash
# 在开发机上编译
CGO_ENABLED=1 go build -ldflags "-s -w" -o hy2-gateway ./cmd/gateway

# 交叉编译到 Linux amd64（需要 C 交叉编译器，因为 SQLite 依赖 CGO）
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o hy2-gateway ./cmd/gateway
```

如果不想处理 CGO 交叉编译，可以直接在目标服务器上编译，或者用 Docker：

```bash
docker build -t hy2-gateway .
```

## 2. 准备 TLS 证书

### 方式 A：用 acme.sh 申请 Let's Encrypt 证书

```bash
# 安装 acme.sh
curl https://get.acme.sh | sh

# 申请证书（DNS 验证或 HTTP 验证）
acme.sh --issue -d your.domain.com --standalone

# 证书路径
# ~/.acme.sh/your.domain.com_ecc/fullchain.cer
# ~/.acme.sh/your.domain.com_ecc/your.domain.com.key
```

### 方式 B：自签证书（测试用）

```bash
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=your.domain.com"
```

客户端需要配置 `insecure: true` 才能连接自签证书的服务器。

## 3. 准备配置文件

```bash
mkdir -p /etc/hy2-gateway
```

创建 `/etc/hy2-gateway/gateway.yaml`：

```yaml
listen: :8443

tls:
  cert: /etc/hy2-gateway/cert.pem
  key: /etc/hy2-gateway/key.pem

# 按需配置混淆（客户端也要配相同密码）
# obfs:
#   type: salamander
#   salamander:
#     password: your_obfs_password

# 按需配置伪装
# masquerade:
#   type: proxy
#   proxy:
#     url: https://www.bing.com
#     rewriteHost: true

users:
  alice:
    password: "change_me_alice"
    route: "node1"
    maxBytes: 107374182400    # 100GB

  bob:
    password: "change_me_bob"
    route: "node2"
    maxBytes: 0               # 不限

nodes:
  node1:
    type: hysteria2
    hysteria2:
      addr: "node1.example.com:443"
      auth: "node1_password"
      # insecure: true        # 如果 node 用自签证书

  node2:
    type: hysteria2
    hysteria2:
      addr: "node2.example.com:443"
      auth: "node2_password"

api:
  listen: "127.0.0.1:9090"   # 只监听本地，不暴露到公网
  secret: "your_api_secret"

dbPath: /var/lib/hy2-gateway/traffic.db
trafficFlushInterval: 10s
```

## 4. 部署

### 方式 A：直接运行

```bash
# 创建数据目录
mkdir -p /var/lib/hy2-gateway

# 复制二进制
cp hy2-gateway /usr/local/bin/

# 运行
hy2-gateway -c /etc/hy2-gateway/gateway.yaml
```

### 方式 B：systemd 服务

创建 `/etc/systemd/system/hy2-gateway.service`：

```ini
[Unit]
Description=Hy2-Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hy2-gateway -c /etc/hy2-gateway/gateway.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/hy2-gateway
ReadOnlyPaths=/etc/hy2-gateway

# 如果监听 443 端口需要这个
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now hy2-gateway
systemctl status hy2-gateway
journalctl -u hy2-gateway -f
```

### 方式 C：Docker

```bash
docker run -d \
  --name hy2-gateway \
  --restart unless-stopped \
  -v /etc/hy2-gateway:/etc/hy2-gateway:ro \
  -v /var/lib/hy2-gateway:/var/lib/hy2-gateway \
  -p 8443:8443/udp \
  -p 9090:9090/tcp \
  hy2-gateway -c /etc/hy2-gateway/gateway.yaml
```

注意：端口映射必须是 **UDP**（`8443/udp`），因为 QUIC 基于 UDP。

## 5. Node 侧部署

Node 只需要一个标准的 hysteria2 server + WARP 出口。

### 5.1 安装 hysteria2

```bash
# 官方安装脚本
bash <(curl -fsSL https://get.hy2.sh/)
```

### 5.2 配置 Node 的 hysteria2 server

`/etc/hysteria/config.yaml`：

```yaml
listen: :443

tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.pem

auth:
  type: password
  password: node1_password    # 与 Gateway 配置中的 auth 一致

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
```

### 5.3 配置 WARP 出口

```bash
# 安装 wgcf
wget https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_linux_amd64 -O /usr/local/bin/wgcf
chmod +x /usr/local/bin/wgcf

# 注册并生成配置
wgcf register
wgcf generate

# 编辑 wgcf-profile.conf，修改 AllowedIPs 避免环路：
# AllowedIPs = 0.0.0.0/0     ← 改为下面的，排除 Gateway 的 IP
# AllowedIPs = 0.0.0.0/1, 128.0.0.0/1

# 启动
cp wgcf-profile.conf /etc/wireguard/wgcf.conf
systemctl enable --now wg-quick@wgcf
```

**重要**：确保 Node 的 hysteria2 server 监听端口的流量不走 WARP（否则会环路）。
可以通过 `PostUp` 规则排除：

```ini
[Interface]
# ...
PostUp = ip rule add from <node_public_ip> table main priority 10
PostDown = ip rule del from <node_public_ip> table main priority 10
```

## 6. 客户端配置

用户使用标准的 Hysteria2 客户端连接 Gateway，配置示例：

```yaml
server: your.gateway.com:8443

auth: alice:change_me_alice

tls:
  sni: your.gateway.com
  # insecure: true            # 自签证书时需要

bandwidth:
  up: 50 mbps
  down: 100 mbps

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

## 7. 验证

```bash
# 检查 Gateway 是否启动
curl -H "Authorization: your_api_secret" http://127.0.0.1:9090/health

# 查看流量统计
curl -H "Authorization: your_api_secret" http://127.0.0.1:9090/traffic

# 查看特定用户
curl -H "Authorization: your_api_secret" http://127.0.0.1:9090/traffic/alice

# 直接查 SQLite（不需要 Gateway 运行）
sqlite3 /var/lib/hy2-gateway/traffic.db "SELECT * FROM traffic_summary;"
```

## 8. 防火墙

```bash
# Gateway 服务器
ufw allow 8443/udp    # hy2 协议（QUIC）
# 不要开放 9090，管理 API 只监听 127.0.0.1

# Node 服务器
ufw allow 443/udp     # hy2 协议（QUIC）
```

## 常见问题

### 客户端连不上

1. 确认防火墙开放了 UDP 端口
2. 确认 TLS 证书域名与客户端 SNI 一致
3. 检查 Gateway 日志：`journalctl -u hy2-gateway -f`

### Node 连不上

Gateway 启动时会立即连接所有配置的 Node。如果连接失败，日志会报错。
`ReconnectableClient` 会自动重试，不需要手动干预。

### 流量统计不准

SQLite 中的数据是定时刷新的（默认 10 秒），实时数据通过 API 查询内存中的值。
如果 Gateway 异常退出，最多丢失一个刷新周期的数据。

### WARP 环路

Node 上如果 hysteria2 server 的流量也走了 WARP，会导致连接失败。
用 `ip rule` 或 WireGuard 的 `AllowedIPs` 排除 Gateway 的 IP。
