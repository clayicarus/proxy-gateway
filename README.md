# Hy2-Gateway

基于 Hysteria2 的多用户网关。客户端显式选择获授权的出站节点，Gateway 负责认证、路由、流量计量、配额和下载限速，并通过 SQLite 和本地 Web 后台管理运行配置。

项目直接实现 Hysteria2 核心接口，不修改上游源码。

## 功能

- `username:node:password` 多用户认证，认证 ID 为 `username:node`
- SQLite 管理用户、节点、用户节点授权、到期、月额度、下载限速和订阅 token
- 仅绑定 loopback 的管理后台：概览、用户、活跃连接、成本和故障分析
- 按配置时区的自然月统计所有节点 `tx + rx`，超额时关闭客户端连接
- 用户级总下载限速，覆盖该用户的全部连接
- 独立的公开订阅 HTTP 服务，生成 Clash.Meta 配置
- systemd 重启调度、watchdog、优雅停机和进程退出原因记录
- Direct、SOCKS5、HTTP CONNECT 和 Hysteria2 出站

服务端没有隐式 fallback。节点缺失、上下文错配或拨号失败都会直接返回错误；`direct` 也必须由客户端明确选择并获用户授权。

## 拓扑

```text
hy2 客户端 --QUIC/UDP--> Gateway --direct/代理/hy2--> Node 或目标
                              |--HTTP/TCP--> 本地管理后台
                              `--HTTP/TCP--> 公开订阅服务
```

详细设计见 [架构文档](docs/ARCHITECTURE.md) 和 [管理后台设计](docs/ADMIN_DESIGN.md)。

## 构建

需要 Go 1.24+ 和 C 编译器，SQLite 驱动依赖 CGO。

```bash
CGO_ENABLED=1 go build -ldflags "-s -w" -o hy2-gateway ./cmd/gateway
CGO_ENABLED=1 go test ./...
```

跨平台构建需要相应的 C 交叉编译器；也可以直接在目标 Linux 机器上构建。

## 快速开始

### 1. 配置启动参数

```yaml
listen: :8443

tls:
  cert: /etc/hy2-gateway/cert.pem
  key: /etc/hy2-gateway/key.pem

admin:
  listen: "127.0.0.1:9090"

sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  serverAddr: "gateway.example.com:8443"
  sni: "gateway.example.com"

dbPath: /var/lib/hy2-gateway/traffic.db
trafficFlushInterval: 10s
timezone: "Asia/Shanghai"

systemd:
  unit: "hy2-gateway.service"
  watchdog: true
```

必须提供 `tls.cert` 与 `tls.key` 证书文件。`listen` 是 Hysteria2 的 UDP 端口；`admin.listen` 和 `sub.listen` 是两个独立的 HTTP/TCP 端口。`sub.publicURL` 是用户获取订阅的 URL 前缀，`sub.serverAddr` 则是订阅内容中客户端连接 Gateway 的地址。

用户和节点不写在正常运行 YAML 中。首次启动后通过管理后台创建。

### 2. 启动

```bash
install -d -o hy2gateway -g hy2gateway -m 0750 /var/lib/hy2-gateway
./hy2-gateway -c /etc/hy2-gateway/gateway.yaml
```

SQLite 数据库目录会自动创建，但运行用户必须能够写入其父目录。systemd 的 `WorkingDirectory` 也会影响相对 `dbPath`；生产环境应使用绝对路径。

### 3. 访问后台

后台没有登录鉴权，配置会强制它只绑定 loopback。通过 SSH 转发访问：

```bash
ssh -L 9090:127.0.0.1:9090 root@gateway.example.com
```

浏览器打开 `http://127.0.0.1:9090`。所有写操作只接受 POST 并校验 CSRF token，敏感操作还会在前端二次确认；Origin/Referer 不作为 SSH 转发环境下的安全边界。

节点定义和用户节点授权在重启后生效。用户密码、停用、到期、额度和限速最多约 2 秒刷新；停用、到期或超额的已有会话会在下一笔有效负载转发前关闭整条 QUIC 连接。完全空闲的会话不会被主动清理，直到客户端断开、再次发送流量、QUIC idle timeout 或 Gateway 重启。

### 4. 客户端连接

```yaml
server: gateway.example.com:8443
auth: alice:node1:generated_password
tls:
  sni: gateway.example.com
```

推荐直接使用后台生成的订阅 URL。订阅中的多个代理条目对应用户获授权的节点，客户端负责选择和故障切换。

## 旧 YAML 迁移

旧部署先保留原 `users`、`nodes` 和 secret，执行：

```bash
hy2-gateway migrate -c /etc/hy2-gateway/legacy-gateway.yaml
```

旧订阅 token 使用 YAML 的 `sub.secret`，缺省时使用 `api.secret`。迁移会将旧 HMAC token 的哈希写入数据库，使已发布链接继续可用。完成后从正常运行 YAML 删除 `users`、`nodes` 和 `fallback`。

需要以旧 YAML 原子替换数据库中的用户和授权时：

```bash
hy2-gateway migrate --replace-users -c /etc/hy2-gateway/legacy-gateway.yaml
```

该命令保留节点、流量、重启和进程历史，但会删除 YAML 中不存在的管理用户。详见 [部署指南](docs/DEPLOYMENT.md)。

## 流量口径

- `tx`：客户端经 Gateway 发往 Node 或目标的数据。
- `rx`：Node 或目标经 Gateway 发往客户端的数据。
- 用户月额度：该用户所有节点的 `tx + rx`。
- Gateway 估算出站：`tx + rx`。
- Node 估算出站：非 `direct` 节点的 `tx + rx`。

这些数值是有效负载估算，不含 QUIC/IP 包头和重传。Node 与 Gateway 的公式是两个服务器视角的成本估算，不能相加后当作某一台机器的流量。

## SQLite

主要表如下：

| 表 | 用途 |
|---|---|
| `managed_users` | 用户、生命周期、额度、限速和 token 哈希 |
| `managed_nodes` | 节点配置与启用状态 |
| `user_nodes` | 用户节点授权 |
| `traffic_logs` | 每次 flush 的流量增量 |
| `traffic_summary` | 用户和节点累计流量 |
| `config_state` | 保存 revision 与运行 revision |
| `management_migrations` | 数据迁移标记 |
| `restart_jobs` | 计划重启任务 |
| `process_runs` | 进程运行和退出历史 |

所有时间字段使用 UTC Unix 秒。直接查询时需要显式转换：

```sql
-- 所有用户累计流量
SELECT user_id, node_id, tx_total, rx_total FROM traffic_summary;

-- 最近 24 小时某用户流量
SELECT SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= unixepoch('now', '-1 day');

-- 按 UTC 日期汇总
SELECT date(created_at, 'unixepoch') AS day,
       SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
GROUP BY day ORDER BY day;

-- 查看本地可读时间
SELECT datetime(created_at, 'unixepoch') AS created_utc, user_id, node_id
FROM traffic_logs ORDER BY created_at DESC LIMIT 20;
```

自然月额度和后台范围查询会按 YAML 的 `timezone` 计算 UTC 边界，不应直接用 SQLite 的本地日期函数替代。

## 配置字段

| 字段 | 说明 |
|---|---|
| `listen` | Gateway Hysteria2 UDP 监听地址，默认 `:443` |
| `tls.cert` / `tls.key` | 必填的 TLS 证书和私钥文件 |
| `admin.listen` | 本地管理后台，必须绑定 loopback |
| `sub.listen` | 独立订阅 HTTP 服务监听地址 |
| `sub.publicURL` | 后台展示的公开订阅 URL 前缀 |
| `sub.serverAddr` | 订阅中客户端连接 Gateway 的公网地址 |
| `sub.sni` / `sub.insecure` | 生成的客户端 TLS 参数 |
| `dbPath` | SQLite 路径，默认 `hy2-gateway.db` |
| `trafficFlushInterval` | 流量写入周期，默认 `10s` |
| `timezone` | 自然月和后台查询时区，默认 `UTC` |
| `systemd.unit` | 后台只允许控制的固定 systemd unit |
| `systemd.watchdog` | 是否发送 systemd watchdog 心跳 |

## 项目结构

```text
cmd/gateway/       启动、迁移、退出记录和生命周期
internal/api/      管理 Web 与数据库订阅服务
internal/auth/     用户认证和热刷新
internal/config/   YAML 启动配置及旧配置解析
internal/connection/ 活跃连接追踪
internal/event/    Hysteria2 事件与路由上下文交接
internal/router/   路由和出站实现
internal/storage/  SQLite schema 与查询
internal/subtoken/ 订阅 token
internal/systemd/  D-Bus 重启和 watchdog 通知
internal/traffic/  流量、配额与下载限速
test/              集成和端到端测试
docs/              设计、集成和部署文档
```

## 文档

- [架构设计](docs/ARCHITECTURE.md)
- [管理后台设计](docs/ADMIN_DESIGN.md)
- [部署指南](docs/DEPLOYMENT.md)
- [Hysteria2 集成说明](docs/INTEGRATION.md)
- [开发路线图](docs/ROADMAP.md)

## License

MIT
