# Hysteria2 核心库集成说明

本文记录 proxy-gateway 与仓库内固定的 `github.com/apernet/hysteria/core/v2` v2.8.1 fork 的当前集成契约，重点是 session 身份、请求路由和流量回调。实际装配入口位于 `cmd/gateway/main.go`。

## 接口映射

| Hysteria2 接口 | 实现 | 责任 |
|---|---|---|
| `server.SessionAuthenticator` | `inbound/hysteria2.Adapter` | 认证并创建绑定 `username:node` 的私有 session |
| `server.SessionOutbound` | `inbound/hysteria2.Adapter` | 将 session 的显式身份交给 `router.Service` |
| `server.SessionTrafficLogger` | `inbound/hysteria2.Adapter` | 在既有 TCP/UDP 计量边界调用共享账本 |
| `server.SessionEventLogger` | `inbound/hysteria2.Adapter` | 按 session/request ID 更新活跃连接追踪 |

只有 Hy2 adapter 实现上游接口，并在代码中有编译期断言；认证、路由、账本和追踪保持协议无关。

## 启动装配

运行配置先从 SQLite 加载，而不是从静态 YAML 用户和节点字段加载：

```go
users, err := store.LoadRuntimeUsers()
nodes, err := store.LoadNodes()

authenticator := auth.NewAuthenticator(users, logger)
trafficLogger := traffic.NewTrafficLoggerWithLocation(users, store, logger, location)
routerEngine := router.NewRouter(users, logger)
outboundFactory := outbound.NewOutboundFactory(nodes, logger)
warmupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
_ = outboundFactory.Warmup(warmupCtx)
cancel()
routingService := router.NewService(routerEngine, outboundFactory, logger)
connectionTracker := connection.NewTracker()
adapter := hysteria2.New("hy2-public", authenticator, routingService, trafficLogger, connectionTracker, logger)
```

然后把实现直接交给 Hysteria2 server：

```go
server, err := hyServer.NewServer(&hyServer.Config{
    TLSConfig: hyServer.TLSConfig{
        Certificates: []tls.Certificate{certificate},
    },
    QUICConfig:             buildInboundQUICConfig(inbound.QUIC),
    Conn:                   udpConn,
    SessionAuthenticator:   adapter,
    SessionOutbound:        adapter,
    SessionTrafficLogger:   adapter,
    SessionEventLogger:     adapter,
})
```

TLS 证书由 `tls.LoadX509KeyPair` 从 YAML 指定的 `tls.cert` 与 `tls.key` 文件加载。

## 认证 ID

`Authenticate` 接收的 auth 形如：

```text
alice:node_tokyo:a-password-that-may:contain-colons
```

解析规则是前两个冒号分隔 username 和 node，余下部分全部作为 password。认证通过必须同时满足：

- 用户存在，未软删除且未到期。
- 密码匹配。
- 用户启动快照授权了所选节点。

返回的 ID 是 `alice:node_tokyo`。adapter 将其保存在私有 session，并将其显式传给 TrafficLogger 和 router.Service；不应退化为仅用户名。

## Session 请求绑定

认证成功后 fork 为该 QUIC transport 建立私有 session。TCP/UDP 回调均携带 session、稳定 request ID 和目标地址：

```text
TCPContext(session, request ID, target) -> router.Service.TCPContext(id, target)
UDPContext(session, request ID, target) -> router.Service.UDPContext(id, target)
```

adapter 会拒绝未知 session；router.Service 会拒绝 ID 缺少节点、未授权节点、未知节点和拨号失败。不能在这些错误上隐式回退到 `direct` 或另一个节点，否则会绕过客户端选择和用户授权。请求身份不依赖 callback 的相对时序，因此相同目标的并发请求可以独立路由。

## 出站适配

`outbound.OutboundFactory` 只提供内建 Direct 与数据库中的 Hysteria2 节点。Direct TCP 使用带 10 秒超时的标准 `net.Dialer`。Hysteria2 outbound 使用 fork 的 `client.NewClientContext`，Gateway 自己管理每个节点的 eager 连接状态和重试生命周期。

启动时最多同时预连接 8 个节点，首轮预热最多等待 10 秒；节点失败互相隔离。请求路径只使用 Ready client，不可用时立即报错；后台以最长 60 秒的指数退避重连。每次尝试都以 3 秒超时重新查询 DNS，并依次尝试 A/AAAA 地址；连接到解析 IP 时仍将配置域名作为默认 SNI。Hy2 握手保留上游默认 5 秒超时。当前每节点一条活动 client 连接，不是连接池。

UDP client 的 `HyUDPConn` 通过轻量 wrapper 适配为协议无关 UDP association 的 `ReadFrom`、`WriteTo` 和 `Close` 签名；仅 adapter 将它暴露给 Hy2 server。

## 流量回调

TrafficLogger 的关键方法包括：

```go
LogTraffic(id string, tx, rx uint64) bool
LogOnlineState(id string, online bool)
TraceStream(stream HyStream, stats *StreamStats)
UntraceStream(stream HyStream)
```

`LogTraffic` 将 ID 拆成 username/node 并累计流量。返回 false 会让上游关闭整个客户端连接，用于停用、到期和月额度超限。用户下载限速只作用于 `rx`，但同一用户所有节点和连接共享限速状态。

`TraceStream` 与 `UntraceStream` 不是空实现：它们提供实时 stream 计数和速度数据。adapter 的 session/request 回调另行记录客户端源地址、所选节点和 TCP/UDP 目标，供本地管理后台展示。

## 热刷新边界

每 2 秒从 SQLite 重新读取用户生命周期字段，并保留进程启动时的 routes：

```text
热刷新：密码、软删除、到期、月额度、下载限速
需重启：新用户、节点定义、节点启停、用户节点授权
```

保留启动 routes 很重要：否则保存后尚未重启的授权可能被认证层提前接受，而 Outbound 仍使用旧节点快照。

## 并发与测试要求

- Authenticator 和 TrafficLogger 的用户快照更新必须受锁保护。
- OutboundFactory 的节点状态和 client 切换必须受每节点锁保护，且后台连接并发数不得超过上限。
- 请求上下文交接必须 fail-closed，不能根据 target 猜测用户。
- `go test -race` 应覆盖 auth、router、traffic 和集成请求链路。
- 至少保留“多用户并发访问相同 target 不串路由”的压力测试。
