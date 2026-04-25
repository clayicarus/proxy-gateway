# Hysteria2 核心库集成指南

## 概述

本文档说明如何将 hy2-gateway 的各个组件与 Hysteria2 核心库 (`github.com/apernet/hysteria/core/v2/server`) 对接。

## Hysteria2 Server 的 Config 结构

```go
// 来自 hysteria/core/v2/server 包
type Config struct {
    TLSConfig       TLSConfig
    QUICConfig      QUICConfig
    Conn            net.PacketConn    // UDP 监听
    Authenticator   Authenticator     // 认证接口
    Outbound        Outbound          // 出站接口
    BandwidthConfig BandwidthConfig   // 带宽配置
    IgnoreClientBandwidth bool
    DisableUDP      bool
    UDPIdleTimeout  time.Duration
    EventLogger     EventLogger       // 事件日志
    TrafficLogger   TrafficLogger     // 流量统计
    RequestHook     RequestHook       // 请求钩子（可选）
}
```

## 接口映射

| Hysteria2 接口 | 我们的实现 | 说明 |
|---|---|---|
| `Authenticator` | `auth.Authenticator` | 解析 username:password，验证后返回 username 作为 ID |
| `Outbound` | `router.RoutingOutbound` | 根据用户上下文选择不同出站节点 |
| `TrafficLogger` | `traffic.TrafficLogger` | 按用户统计流量，支持配额限制 |
| `EventLogger` | `event.EventLogger` | 桥接事件系统，在请求前设置用户路由上下文 |

## 关键时序

Hysteria2 处理一个 TCP 代理请求的调用顺序：

```
1. Client connects (QUIC handshake)
2. Authenticator.Authenticate(addr, auth, tx)
   → 返回 (ok=true, id="alice")
3. EventLogger.Connect(addr, id="alice", tx)
   → 我们在这里记录 addr→alice 的映射
4. Client sends TCP proxy request for "google.com:443"
5. EventLogger.TCPRequest(addr, id="alice", reqAddr="google.com:443")
   → 我们在这里设置请求上下文: (addr, "google.com:443") → "alice"
6. Outbound.TCP("google.com:443")
   → RoutingOutbound 查找请求上下文，得知是 alice
   → 查找 alice 的路由: node_tokyo
   → 通过 node_tokyo (SOCKS5) 连接到 google.com:443
7. TrafficLogger.LogTraffic(id="alice", tx, rx)
   → 累加 alice 的流量统计
   → 检查是否超过配额
8. Client disconnects
9. EventLogger.Disconnect(addr, id="alice", err)
   → 清理 addr→alice 的映射
```

## 完整集成代码

```go
package main

import (
    "crypto/tls"
    "net"
    "time"

    hyServer "github.com/apernet/hysteria/core/v2/server"
    "github.com/hy2-gateway/internal/auth"
    "github.com/hy2-gateway/internal/config"
    "github.com/hy2-gateway/internal/event"
    "github.com/hy2-gateway/internal/router"
    "github.com/hy2-gateway/internal/traffic"
)

func startHysteriaServer(cfg *config.Config) error {
    // 1. 创建 UDP 监听
    udpAddr, _ := net.ResolveUDPAddr("udp", cfg.Listen)
    conn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        return err
    }

    // 2. 加载 TLS 证书
    cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
    if err != nil {
        return err
    }

    // 3. 初始化我们的组件
    authenticator := auth.NewAuthenticator(cfg.Users, logger)
    trafficLogger := traffic.NewTrafficLogger(cfg.Users, logger)
    routerEngine := router.NewRouter(cfg.Users, logger)
    outboundFactory := router.NewOutboundFactory(cfg.Nodes, logger)
    routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
    eventLogger := event.NewEventLogger(routingOutbound, logger)

    // 4. 创建 Hysteria2 服务器
    server, err := hyServer.NewServer(&hyServer.Config{
        TLSConfig: hyServer.TLSConfig{
            Certificates: []tls.Certificate{cert},
        },
        QUICConfig: hyServer.QUICConfig{
            MaxIdleTimeout:    30 * time.Second,
            MaxIncomingStreams: 1024,
        },
        Conn:          conn,
        Authenticator: authenticator,
        Outbound:      routingOutbound,  // 类型需要适配
        TrafficLogger: trafficLogger,    // 类型需要适配
        EventLogger:   eventLogger,      // 类型需要适配
    })
    if err != nil {
        return err
    }

    // 5. 启动服务
    return server.Serve()
}
```

## 接口适配

由于我们的类型和 Hysteria2 的接口定义在不同的包中，需要做类型适配。
有两种方式：

### 方式 A：直接实现 Hysteria2 的接口（推荐）

让我们的类型直接 import 并实现 `github.com/apernet/hysteria/core/v2/server` 包中的接口。
这需要在 go.mod 中添加 hysteria 依赖。

### 方式 B：适配器模式

创建 thin wrapper 来桥接类型差异：

```go
// adapter.go
type outboundAdapter struct {
    inner *router.RoutingOutbound
}

func (a *outboundAdapter) TCP(reqAddr string) (net.Conn, error) {
    return a.inner.TCP(reqAddr)
}

func (a *outboundAdapter) UDP(reqAddr string) (hyServer.UDPConn, error) {
    // 需要将 router.UDPConn 适配为 hyServer.UDPConn
    conn, err := a.inner.UDP(reqAddr)
    if err != nil {
        return nil, err
    }
    return conn, nil // 如果接口签名一致则直接返回
}
```

## TrafficLogger 的 TraceStream/UntraceStream

Hysteria2 v2.6.5 的 TrafficLogger 接口还包含：

```go
type TrafficLogger interface {
    LogTraffic(id string, tx, rx uint64) (ok bool)
    LogOnlineState(id string, online bool)
    TraceStream(stream HyStream, stats *StreamStats)
    UntraceStream(stream HyStream)
}
```

`TraceStream`/`UntraceStream` 用于 `/dump/streams` API。
如果不需要这个功能，可以提供空实现：

```go
func (tl *TrafficLogger) TraceStream(stream hyServer.HyStream, stats *hyServer.StreamStats) {}
func (tl *TrafficLogger) UntraceStream(stream hyServer.HyStream) {}
```

## 注意事项

1. **线程安全**：所有接口实现必须是线程安全的，Hysteria2 会从多个 goroutine 并发调用
2. **时序依赖**：我们的路由方案依赖 EventLogger 在 Outbound 之前被调用，
   这在当前 Hysteria2 实现中是成立的，但未来版本可能改变
3. **UDP 会话**：UDP 的路由比 TCP 复杂，因为一个 UDP 会话可能发送到多个目标地址
4. **性能**：sync.Map 的遍历（Range）在高并发下可能成为瓶颈，
   如果用户量很大，考虑使用分片 map 或其他并发数据结构
