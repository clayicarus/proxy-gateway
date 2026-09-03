# Hysteria2 核心库集成说明

本文记录 proxy-gateway 与 `github.com/apernet/hysteria/core/v2` 的当前集成契约，重点是认证 ID、请求路由上下文和流量回调。实际装配入口位于 `cmd/gateway/main.go`。

## 接口映射

| Hysteria2 接口 | 实现 | 责任 |
|---|---|---|
| `server.Authenticator` | `auth.Authenticator` | 解析 `username:node:password`，返回 `username:node` |
| `server.Outbound` | `router.RoutingOutbound` | 从认证 ID 选择客户端明确指定的节点 |
| `server.TrafficLogger` | `traffic.TrafficLogger` | 统计、自然月额度、下载限速和 stream 追踪 |
| `server.EventLogger` | `event.EventLogger` | 请求上下文交接和活跃连接追踪 |

这些类型直接实现上游接口，并在代码中有编译期断言，不需要额外 adapter。

## 启动装配

运行配置先从 SQLite 加载，而不是从静态 YAML 用户和节点字段加载：

```go
users, err := store.LoadRuntimeUsers()
nodes, err := store.LoadNodes()

authenticator := auth.NewAuthenticator(users, logger)
trafficLogger := traffic.NewTrafficLoggerWithLocation(users, store, logger, location)
routerEngine := router.NewRouter(users, logger)
outboundFactory := router.NewOutboundFactory(nodes, logger)
warmupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
_ = outboundFactory.Warmup(warmupCtx)
cancel()
routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
connectionTracker := connection.NewTracker()
eventLogger := event.NewEventLogger(routingOutbound, logger, connectionTracker)
```

然后把实现直接交给 Hysteria2 server：

```go
server, err := hyServer.NewServer(&hyServer.Config{
    TLSConfig: hyServer.TLSConfig{
        Certificates: []tls.Certificate{certificate},
    },
    QUICConfig:    buildQUICConfig(cfg),
    Conn:          udpConn,
    Authenticator: authenticator,
    Outbound:      routingOutbound,
    TrafficLogger: trafficLogger,
    EventLogger:   eventLogger,
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

返回的 ID 是 `alice:node_tokyo`。TrafficLogger、EventLogger 和 Router 都使用这个 ID，不应退化为仅用户名。

## 请求上下文交接

上游 `server.Outbound` 的 `TCP(reqAddr)` 和 `UDP(reqAddr)` 没有 ID 参数。当前 Hysteria2 请求处理顺序会先调用 EventLogger，再调用 Outbound：

```text
TCPRequest(addr, id, target) -> TCP(target)
UDPRequest(addr, id, sessionID, target) -> UDP(target)
```

EventLogger 调用 `RoutingOutbound.SetRequestContext`，把协议、认证 ID、客户端地址和目标放入容量为 1 的 channel。Outbound 非阻塞取出下一项，并核对协议与目标：

- 缺少上下文：返回错误。
- 协议或目标不一致：返回错误。
- ID 缺少节点：返回错误。
- 节点不存在或拨号失败：返回错误。

不能在这些错误上隐式回退到 `direct` 或另一个节点，否则会绕过客户端选择和用户授权。容量为 1 的交接会短暂串行化事件回调到 Outbound 的临界段，避免相同目标的并发请求交换用户身份；拨号和 relay 不在该临界段内。

这是与上游实现时序耦合最强的部分。升级 Hysteria2 依赖时，应运行路由并发测试和真实端到端测试，并复核上游 TCP/UDP handler 的调用顺序。

## 出站适配

`OutboundFactory` 只提供内建 Direct 与数据库中的 Hysteria2 节点。Direct TCP 使用带 10 秒超时的标准 `net.Dialer`。Hysteria2 outbound 使用上游 `client.NewClient`，Gateway 自己管理每个节点的 eager 连接状态和重试生命周期。

启动时最多同时预连接 8 个节点，首轮预热最多等待 10 秒；节点失败互相隔离。请求路径只使用 Ready client，不可用时立即报错；后台以最长 60 秒的指数退避重连。每次尝试都以 3 秒超时重新查询 DNS，并依次尝试 A/AAAA 地址；连接到解析 IP 时仍将配置域名作为默认 SNI。Hy2 握手保留上游默认 5 秒超时。当前每节点一条活动 client 连接，不是连接池。

UDP client 的 `HyUDPConn` 通过轻量 wrapper 适配为 `server.UDPConn` 的 `ReadFrom`、`WriteTo` 和 `Close` 签名。

## 流量回调

TrafficLogger 的关键方法包括：

```go
LogTraffic(id string, tx, rx uint64) bool
LogOnlineState(id string, online bool)
TraceStream(stream HyStream, stats *StreamStats)
UntraceStream(stream HyStream)
```

`LogTraffic` 将 ID 拆成 username/node 并累计流量。返回 false 会让上游关闭整个客户端连接，用于停用、到期和月额度超限。用户下载限速只作用于 `rx`，但同一用户所有节点和连接共享限速状态。

`TraceStream` 与 `UntraceStream` 不是空实现：它们提供实时 stream 计数和速度数据。EventLogger 另行记录客户端源地址、所选节点和 TCP/UDP 目标，供本地管理后台展示。

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
