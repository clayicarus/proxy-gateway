# Hy2-Gateway

基于 Hysteria2 协议的多用户网关，支持按用户名路由、鉴权和流量统计。

不修改 Hysteria2 源码，通过实现其核心接口注入业务逻辑，与上游保持兼容。

## 功能

- **多用户认证**：`username:node:password` 模式，标准 hy2 客户端直接连接
- **按用户路由**：不同用户的流量路由到不同的出口节点，支持多节点选择
- **Fallback 策略**：节点不可用时可配置 fallback 到其他节点、直连或拒绝
- **流量统计**：按用户实时统计 tx/rx，支持配额限制（超额自动断开）
- **SQLite 持久化**：流量数据定时写入 SQLite，进程重启不丢失
- **hy2 Client Pool**：Gateway 到 Node 使用 QUIC 长连接，自动重连
- **管理 API**：HTTP 接口查询流量、健康检查

## 架构

```
用户 ──hy2──→ Gateway(认证 + 路由 + 统计) ──hy2──→ Node(hy2 server + WARP) ──→ 互联网
```

详细架构设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 构建

需要 Go 1.22+ 和 C 编译器（SQLite 依赖 CGO）。

```bash
# 构建
CGO_ENABLED=1 go build -ldflags "-s -w" -o hy2-gateway ./cmd/gateway

# 运行测试
CGO_ENABLED=1 go test ./...

# Docker 构建
docker build -t hy2-gateway .
```

交叉编译到 Linux amd64（在 macOS/其他平台上）：

```bash
# 需要安装交叉编译工具链，如 musl-cross 或 zig cc
CGO_ENABLED=1 CC=x86_64-linux-musl-gcc \
  GOOS=linux GOARCH=amd64 \
  go build -ldflags "-s -w -linkmode external -extldflags '-static'" \
  -o hy2-gateway ./cmd/gateway
```

或者直接在目标 Linux 服务器上编译，避免交叉编译的麻烦。

## 快速开始

### 1. 准备配置

```yaml
# /etc/hy2-gateway/gateway.yaml
listen: :8443

tls:
  cert: /etc/hy2-gateway/cert.pem
  key: /etc/hy2-gateway/key.pem

users:
  alice:
    password: "alice_password"
    routes:
      - node1
      - direct
    fallback: "direct"            # node1 不可用时走直连
    maxBytes: 107374182400        # 100GB
  bob:
    password: "bob_password"
    routes:
      - node1
    fallback: "node2"             # node1 不可用时走 node2

nodes:
  node1:
    type: hysteria2
    hysteria2:
      addr: "node1.example.com:443"
      auth: "node1_secret"
      insecure: true
  node2:
    type: hysteria2
    hysteria2:
      addr: "node2.example.com:443"
      auth: "node2_secret"
      insecure: true

api:
  listen: "127.0.0.1:9090"
  secret: "your_api_secret"

dbPath: /var/lib/hy2-gateway/traffic.db
```

### 2. 运行

```bash
mkdir -p /var/lib/hy2-gateway
./hy2-gateway -c /etc/hy2-gateway/gateway.yaml
```

### 3. 客户端连接

标准 Hysteria2 客户端，auth 格式为 `username:node:password`：

```yaml
server: your.gateway.com:8443
auth: alice:node1:alice_password
bandwidth:
  up: 50 mbps
  down: 100 mbps
socks5:
  listen: 127.0.0.1:1080
```

### 4. 查看流量

```bash
# API 查询
curl -H "Authorization: your_api_secret" http://127.0.0.1:9090/traffic

# 直接查 SQLite
sqlite3 /var/lib/hy2-gateway/traffic.db "SELECT * FROM traffic_summary;"
```

## 数据库表结构

SQLite 中有两张表：

**traffic_summary** — 每个用户+节点的累计流量汇总

| 字段 | 类型 | 说明 |
|------|------|------|
| `user_id` | TEXT | 用户名 |
| `node_id` | TEXT | 节点名 |
| `tx_total` | INTEGER | 累计上传字节数（服务端→目标） |
| `rx_total` | INTEGER | 累计下载字节数（目标→服务端） |
| `updated_at` | DATETIME | 最后更新时间 |

**traffic_logs** — 增量流量明细（每次 flush 写入一条）

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER | 自增主键 |
| `user_id` | TEXT | 用户名 |
| `node_id` | TEXT | 节点名 |
| `tx_bytes` | INTEGER | 本次增量上传字节数 |
| `rx_bytes` | INTEGER | 本次增量下载字节数 |
| `created_at` | DATETIME | 记录时间 |

### 常用查询

```sql
-- 所有用户累计流量
SELECT user_id, node_id, tx_total, rx_total FROM traffic_summary;

-- 某用户累计流量
SELECT node_id, tx_total, rx_total FROM traffic_summary WHERE user_id = 'alice';

-- 某用户今天的流量
SELECT SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= date('now');

-- 某用户本月每天的流量
SELECT date(created_at) AS day, SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= date('now', 'start of month')
GROUP BY day ORDER BY day;

-- 某用户按节点分组的今日流量
SELECT node_id, SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= date('now')
GROUP BY node_id;

-- 所有用户今日流量排行
SELECT user_id, SUM(tx_bytes + rx_bytes) AS total
FROM traffic_logs
WHERE created_at >= date('now')
GROUP BY user_id ORDER BY total DESC;
```

## 配置说明

| 字段 | 说明 |
|------|------|
| `listen` | 监听地址，默认 `:443` |
| `tls.cert` / `tls.key` | TLS 证书和私钥路径 |
| `users.<name>.password` | 用户密码 |
| `users.<name>.routes` | 可用节点列表，`direct` 或 nodes 中的名称 |
| `users.<name>.fallback` | 节点不可用时的策略：`reject`（默认）/ `direct` / 其他节点名 |
| `users.<name>.maxBytes` | 流量配额（字节），0 为不限 |
| `nodes.<name>.type` | 出站类型：`direct` / `socks5` / `http` / `hysteria2` |
| `api.listen` | 管理 API 监听地址，建议只绑定 127.0.0.1 |
| `api.secret` | API 鉴权密钥 |
| `dbPath` | SQLite 数据库路径，默认 `hy2-gateway.db` |
| `trafficFlushInterval` | 流量写入 SQLite 的间隔，默认 `10s` |

## 项目结构

```
cmd/gateway/          程序入口
internal/
  auth/               用户认证
  router/             路由引擎 + 各类出站实现
  traffic/            流量统计 + 配额
  storage/            SQLite 持久化
  event/              事件日志（用户上下文桥接）
  api/                管理 HTTP API
  config/             配置解析
test/
  integration/        组件级集成测试
  e2e/                真实 hy2 客户端端到端测试
docs/                 文档
```

## 文档

- [架构设计](docs/ARCHITECTURE.md)
- [部署指南](docs/DEPLOYMENT.md)
- [Hysteria2 集成说明](docs/INTEGRATION.md)
- [开发路线图](docs/ROADMAP.md)

## License

MIT
