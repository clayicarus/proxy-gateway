[English](README.md) | **中文**

# Proxy Gateway

支持 Hysteria2 与 Trojan 入站的多用户网关。客户端显式选择获授权的出站节点，Gateway 负责认证、路由、流量计量、配额和下载限速，并通过 SQLite 和本地 Web 后台管理运行配置。

项目固定使用基于 Hysteria2 core v2.8.1 的仓库内最小补丁；补丁只增加请求身份、取消和完整生命周期能力，不修改 wire protocol。

## 功能

- `username:node:password` 多用户认证，认证 ID 为 `username:node`
- SQLite 管理用户、节点、用户节点授权、到期、月额度、下载限速和订阅 token
- 仅绑定 loopback 的管理后台：概览、用户、活跃连接、成本和故障分析
- 按配置时区的自然月统计所有节点 `tx + rx`，超额时关闭客户端连接
- 用户级总下载限速，覆盖该用户的全部连接
- 独立的公开订阅 HTTP 服务，生成 Hysteria2、Trojan 或两者混合的 Clash.Meta / Mihomo 配置
- systemd 重启调度、watchdog、优雅停机和进程退出原因记录
- 内建 Direct 和远端 Hysteria2 出站
- Trojan 入站，支持 TCP CONNECT 与 UDP ASSOCIATE，使用每个用户、节点独立的派生凭据
- 两种入站均可选提供网站：Hysteria2 HTTP/3 伪装和 Trojan HTTPS 回退到配置指定的 web 后端

Gateway 不会自动切换代理请求的出站节点。节点缺失、上下文错配或拨号失败都会直接返回错误；`direct` 也必须由客户端明确选择并获用户授权。

Gateway 启动时并发预连接所有启用的 Hysteria2 节点，最多同时连接 8 个并等待首轮结果 10 秒。单节点失败不会阻止其他节点或 Gateway 启动；请求遇到不可用节点会立即失败，节点在后台以带 jitter 的指数退避重连（最长 60 秒）。每次连接尝试都重新查询 DNS，应用本身不缓存结果；系统解析器仍可能使用操作系统或上游 DNS 缓存。管理后台显示节点状态、实际解析地址、最近成功、错误和下次重试时间。

## 拓扑

```text
hy2 客户端 --QUIC/UDP--> Gateway --direct/hy2--> Node 或目标
trojan 客户端 --TLS/TCP--> Gateway --direct/hy2--> Node 或目标
                              |--HTTP/TCP--> 本地管理后台
                              `--HTTP/TCP--> 公开订阅服务
```

详细设计见 [架构文档](docs/ARCHITECTURE.md) 和 [管理后台设计](docs/ADMIN_DESIGN.md)。

## 构建

需要 Go 1.24+ 和 C 编译器，SQLite 驱动依赖 CGO。

```bash
CGO_ENABLED=1 go build -ldflags "-s -w" -o proxy-gateway ./cmd/gateway
CGO_ENABLED=1 go test ./...
```

跨平台构建需要相应的 C 交叉编译器；也可以直接在目标 Linux 机器上构建。

## 快速开始

### 1. 配置启动参数

```yaml
inbounds:
  - name: hy2-public
    type: hysteria2
    listen: :8443
    masquerade:
      type: proxy
      proxy:
        url: http://127.0.0.1:8080
        rewriteHost: true
  - name: trojan-public
    type: trojan
    listen: :8443
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 256
      udpIdleTimeout: 60s

tls:
  cert: /etc/proxy-gateway/cert.pem
  key: /etc/proxy-gateway/key.pem

admin:
  listen: "127.0.0.1:9090"

sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  endpoints:
    - inbound: hy2-public
      serverAddr: "gateway.example.com:8443"
      sni: "gateway.example.com"
    - inbound: trojan-public
      serverAddr: "gateway.example.com:8443"
      sni: "gateway.example.com"

dbPath: /var/lib/proxy-gateway/traffic.db
trafficFlushInterval: 10s
timezone: "Asia/Shanghai"

systemd:
  unit: "proxy-gateway.service"
  watchdog: true
```

必须提供 `tls.cert` 与 `tls.key` 证书文件。`inbounds` 可配置具名的 Hysteria2 UDP 或 Trojan TCP 入口；两者可以共用数值端口。Hysteria2 入站的 `masquerade` 是可选的，见下文"入站伪装"。`sub.endpoints` 列出要发布的 Hysteria2 或 Trojan 入口，各自配置公网地址和 TLS 参数；`admin.listen` 和 `sub.listen` 是两个独立的 HTTP/TCP 端口。`sub.publicURL` 是用户获取订阅的 URL 前缀，每个 `serverAddr` 则是订阅内容中客户端连接该入口的地址，必须显式配置，不能从监听地址推断。

用户和节点不写在正常运行 YAML 中。首次启动后通过管理后台创建。

### 2. 启动

```bash
install -d -o proxygateway -g proxygateway -m 0750 /var/lib/proxy-gateway
./proxy-gateway -c /etc/proxy-gateway/gateway.yaml
```

SQLite 数据库目录会自动创建，但运行用户必须能够写入其父目录。systemd 的 `WorkingDirectory` 也会影响相对 `dbPath`；生产环境应使用绝对路径。

### 3. 访问后台

后台没有登录鉴权，配置会强制它只绑定 loopback。通过 SSH 转发访问：

```bash
ssh -L 9090:127.0.0.1:9090 root@gateway.example.com
```

浏览器打开 `http://127.0.0.1:9090`。所有写操作只接受 POST 并校验 CSRF token，敏感操作还会在前端二次确认；Origin/Referer 不作为 SSH 转发环境下的安全边界。

节点定义和用户节点授权在重启后生效。用户密码、停用、到期、额度和限速最多约 2 秒刷新；停用、到期或超额的已有会话会在下一笔有效负载转发前关闭对应的 QUIC 连接或 Trojan 会话。完全空闲的会话不会被主动扫描清理；协议超时、客户端断开或 Gateway 重启仍可关闭会话。

### 4. 客户端连接

```yaml
server: gateway.example.com:8443
auth: alice:node1:generated_password
tls:
  sni: gateway.example.com
```

推荐直接使用后台生成的订阅 URL。订阅中的多个代理条目对应用户获授权的节点，客户端负责选择和故障切换。

### Clash.Meta / Mihomo 订阅

同一订阅为每个已授权节点与每个公开入口生成独立条目。上例同时提供 Hysteria2 和 Trojan，完整文件见 [configs/gateway-mixed.yaml](configs/gateway-mixed.yaml)；仅需单入口时，也可以保留原有写法并选择 Trojan：

```yaml
sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  inbound: trojan-public
  serverAddr: "gateway.example.com:8443"
  sni: "gateway.example.com"
```

`sub.endpoints` 与顶层的 `sub.inbound/serverAddr/sni/insecure` 不能混用。每个入口只能列出一次，其公网端口可与监听端口不同；IPv6 地址使用 `[2001:db8::1]:443` 格式。每个条目的 `sni` 和 `insecure` 独立生效，默认验证证书。

Trojan 条目输出 `type: trojan`、原始 `username:node:password` 和 `udp: true`。混合订阅的节点名称带协议后缀，同协议多个入口还带入口名称；重复别名自动消歧，原有单 Hysteria2 订阅保留节点名称。选择组包含所有生成的条目和客户端本地的 `DIRECT`。经 Gateway 直连的 `direct` 条目仍需用户明确获得该节点授权。

不支持 Hysteria2 的旧 Clash 内核应使用仅 Trojan 的订阅。节点授权以启动时快照为准，密码与用户状态实时读取；新用户需重启后才可订阅，重置订阅 token 后旧链接立即失效。订阅包含客户端凭据，响应使用 `Cache-Control: no-store`。

### Trojan 客户端连接

Trojan 支持 TCP CONNECT、UDP ASSOCIATE 和可选的 HTTPS 网站回退，不支持 BIND 或 mux。UDP 数据报走同一条 TCP/TLS 连接，不额外监听 UDP 端口；每条 association 使用与 TCP 相同的节点授权、配额和限速。每个用户和获授权节点使用一个独立 password：

```text
username:node:password
```

客户端应将这个原始值作为 Trojan password；协议在 TLS 内发送其 SHA-224。派生凭据不额外持久化或写入日志；订阅会输出客户端所需的原始值。一个用户有多个节点时，订阅中的多个 Trojan 条目用于显式选择节点。

`trojan.udpIdleTimeout` 只回收双向都没有数据报的 UDP association，默认 60s。

### 入站伪装

不配置 `masquerade` 时，Hysteria2 入站对所有非认证的 HTTP/3 请求返回 404。配置 `type: proxy` 后，这些请求被转发到一个固定的 web 后端，端点表现为一个普通网站：

```yaml
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:8080
    rewriteHost: true
```

- `url` 是配置里的固定值，不受请求内容影响，入站不会变成开放代理。建议指向本机源站而不是绕回自己的公网域名，后者每次探测都要多一次公网 TLS 往返，且域名解析到本机时可能形成环路。
- `rewriteHost: true` 让后端看到自己的 hostname，适合按虚拟主机分发；默认保留探测者发来的 Host。
- Gateway 不发送 `X-Forwarded-*` 和 `Forwarded`，后端不可用时返回空的 502。
- 此设置覆盖 Hysteria2 UDP 端口上的 HTTP/3。普通 HTTPS 使用 TCP，需要另行配置下面的 Trojan 回退。

Trojan 入站的 `trojan.fallback` 会在 TLS 成功后，将无有效凭据的连接转交给固定的明文 HTTP/1.1 后端：

```yaml
trojan:
  fallback:
    addr: 127.0.0.1:8080
    probeTimeout: 1s
    dialTimeout: 3s
    timeout: 30s
    maxConnections: 32
```

- `addr` 是固定的 `host:port`，不能填写 URL 或 TLS 后端。包括 Host 在内的请求字节原样保留，客户端不能选择后端目标；应指向 HTTP 源站，不能指回 Gateway 的公网 TLS 入口。
- TLS 成功后，凭据必须在 `probeTimeout` 内到达，且不能超过原有握手 deadline。未知凭据、格式错误和短首包共用这个判定窗口，因此网站每条 TLS 连接的首次响应会等待约一个窗口，默认一秒。已认证客户端仍可使用原有的请求解析时限。
- TLS ALPN 只声明 `http/1.1`，该入口生成的 Trojan 订阅包含 `alpn: [http/1.1]`。手动配置客户端时应使用相同设置；不发送 ALPN 的客户端也可连接。不提供 HTTP/2 转换。
- `maxConnections` 限制匿名连接数，包括等待判定的连接；`timeout` 限制判定结束后拨号与转发的总时长，`dialTimeout` 另行限制拨号耗时，默认值如上。网站流量不归属代理用户，不进入用户额度、下载限速和计费统计。停机关闭两端，并等待转发结束。
- 已读取的凭据字节按顺序回放一次，部分读取和超时也不丢失数据。已认证但命令非法的连接仍会关闭；后端故障时关闭连接，不生成 Gateway 响应。省略 `fallback` 时保留认证失败即关闭的行为。

完整的[网站配置](configs/gateway-website.yaml)在 TCP 和 UDP 443 上提供同一份 [Field Notes 示例页面](configs/masquerade-site/index.html)。本地试用页面时，在仓库根目录运行：

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory configs/masquerade-site
```

正式部署时，将页面复制到 `/var/www/field-notes/`，并在 Nginx 的 `http` 上下文中包含[源站配置](configs/masquerade-nginx.conf)。该配置监听 loopback 8080，声明公网 443 的 HTTP/3 服务，并将 `/sub/` 转发到独立的 9091 订阅服务。在 `gateway-website.yaml` 中设置域名和证书路径；页面可替换为自己的静态网站。Python 演示仅提供文件，不发布订阅。端口与 TLS 部署详见[部署指南](docs/DEPLOYMENT.md)。

## 旧 YAML 迁移

旧部署先保留原 `users`、`nodes` 和 secret，执行：

```bash
migrate -c /etc/proxy-gateway/legacy-gateway.yaml
```

旧订阅 token 使用 YAML 的 `sub.secret`，缺省时使用 `api.secret`。迁移会将旧 HMAC token 的哈希写入数据库，使已发布链接继续可用。数据库迁移完成后，再将不含管理数据和 secret 的旧运行参数转换为唯一运行时 schema：

```bash
scripts/migrate-inbounds --input /etc/proxy-gateway/legacy-runtime.yaml --output /etc/proxy-gateway/gateway.yaml
scripts/validate-inbounds --input /etc/proxy-gateway/gateway.yaml
```

运行时明确拒绝旧顶层 `listen/quic/api` 以及 `users`、`nodes`、`obfs`、`masquerade`。旧配置同时提供启用的 Trojan 入站、订阅设置和 `trojan.serverAddr` 时，迁移会保留其公网地址、SNI 与证书校验选项，生成混合订阅，并提示新增的 Trojan 发布行为。

需要以旧 YAML 原子替换数据库中的用户和授权时：

```bash
migrate --replace-users -c /etc/proxy-gateway/legacy-gateway.yaml
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
-- Cumulative traffic for all users
SELECT user_id, node_id, tx_total, rx_total FROM traffic_summary;

-- User traffic during the last 24 hours
SELECT SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= unixepoch('now', '-1 day');

-- Aggregate by UTC date
SELECT date(created_at, 'unixepoch') AS day,
       SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
GROUP BY day ORDER BY day;

-- Display readable UTC timestamps
SELECT datetime(created_at, 'unixepoch') AS created_utc, user_id, node_id
FROM traffic_logs ORDER BY created_at DESC LIMIT 20;
```

自然月额度和后台范围查询会按 YAML 的 `timezone` 计算 UTC 边界，不应直接用 SQLite 的本地日期函数替代。

## 配置字段

| 字段 | 说明 |
|---|---|
| `inbounds[].listen` | 具名 Hysteria2 UDP 或 Trojan TCP 监听地址 |
| `inbounds[].masquerade` | 可选的 Hysteria2 HTTP/3 固定网站反向代理 |
| `inbounds[].trojan.fallback` | 可选的 Trojan HTTPS 回退，使用固定 HTTP/1.1 后端与独立资源上限 |
| `tls.cert` / `tls.key` | 必填的 TLS 证书和私钥文件 |
| `admin.listen` | 本地管理后台，必须绑定 loopback |
| `sub.listen` | 独立订阅 HTTP 服务监听地址 |
| `sub.publicURL` | 后台展示的公开订阅 URL 前缀 |
| `sub.inbound` | 单入口订阅绑定的 Hysteria2 或 Trojan 名称 |
| `sub.serverAddr` | 单入口订阅中客户端连接 Gateway 的公网地址 |
| `sub.endpoints[]` | 多入口订阅，每项含 `inbound/serverAddr/sni/insecure` |
| `sub.sni` / `sub.insecure` | 生成的客户端 TLS 参数 |
| `dbPath` | SQLite 路径，默认 `proxy-gateway.db` |
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
internal/inbound/  协议 adapter 与协议库边界
internal/outbound/ Direct、Hy2 node client、重试与连接资源管理
internal/router/   协议无关的策略路由
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
