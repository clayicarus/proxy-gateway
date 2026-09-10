# Trojan 入站 TODO

本清单对应 [Trojan 入站设计](TROJAN_INBOUND_DESIGN.md)。完成标准是 TCP CONNECT 与 UDP ASSOCIATE 在身份、路由、流量与生命周期上与现有 Hy2 行为一致，而不是仅能建立一个 Trojan 连接。

勾选项表示仓库内已有实现和对应测试。未勾选项仍是缺口，不因架构就绪而视为完成。

## 阶段 0：先锁定契约

- [x] 确认支持 TCP CONNECT 与 UDP ASSOCIATE；拒绝 BIND、mux 和 fallback。
- [x] 确认 Trojan 原始 password 固定为 `username:node:password`，每个用户节点组合独立。
- [x] 决定当前只提供手工客户端配置；Trojan 订阅输出留到后续，`serverAddr`/`sni`/`insecure` 届时一并加入。
- [x] 明确未认证连接的 TLS 握手与首包解析超时、并发上限，以及 UDP association 的空闲上限（`handshakeTimeout`、`maxPendingConnections`、`udpIdleTimeout`）。
- [ ] 补充上述阈值的压测依据；当前默认值是保守常量，没有实测支撑。

## 阶段 1：配置与身份索引

- [x] 在 `internal/config` 的 `inbounds` 列表中支持 `type: trojan` 及其参数，并测试未配置、有效地址、跨类型字段与冲突地址。
- [x] 在 `internal/inbound/trojan` 实现不可变 `SHA224(raw password) -> id` 索引；仅接受 56 位小写十六进制哈希。
- [x] 从启动 `users` 快照构建索引，确保 `direct` 也能作为显式授权节点。
- [x] 用户刷新任务对保留启动 routes 的 `updated` 快照同步替换共享认证快照，Hy2 与 Trojan 使用同一份。
- [x] 测试密码变更后旧凭据失效，以及停用用户的后续 payload 被拒绝。
- [ ] 补齐到期、新用户和授权变更在 Trojan 路径上的生效边界测试；后两者重启前必须保持不可用。
- [x] 日志、错误对象和测试失败输出都不含原始 Trojan password 或认证哈希。

## 阶段 2：Trojan 服务

- [x] 独立 TCP listener、TLS `HandshakeContext`、握手/首包 deadline、accept 错误退避与连接追踪。
- [x] 精确解析 `SHA224(password) + CRLF + 命令 + address + port + CRLF`，拒绝截断、超长、未知 ATYP、空域名、非法域名字符、零端口和不支持的命令。
- [x] 通过 `Kernel.AuthenticateTrojan` 取得私有 session，再由 `Kernel.OpenTCP` 选择出站；adapter 拿不到路由 ID 或裸 outbound。
- [x] 实现双向计量 TCP relay；准入返回 false 时关闭两端且不再转发。
- [x] 实现 UDP ASSOCIATE：`Kernel.OpenUDP` 打开出站 flow，逐 datagram 分帧、准入与转发，空闲回收，单包失败只丢包。
- [x] 认证成功后维护在线状态、`Tracker` 会话与 TCP/UDP request 状态；所有退出路径恰好清理一次。
- [x] 服务错误纳入 `inbound.Manager` 的启停与错误路径；停机时停止 accept、关闭活动连接与出站 flow 并等待 goroutine 退出。

## 阶段 3：测试与验收

- [x] 单元测试 SHA-224 索引、热刷新、哈希格式和用户节点映射。
- [x] 表驱动解析测试：IPv4、IPv6、最长域名、截断首包、错误 CRLF、错误命令、非法端口、非法域名字符。
- [x] 表驱动 UDP 分帧测试：往返编码、逐包边界、零端口、错误 CRLF、超出缓冲的长度、截断 payload。
- [x] `FuzzReadRequest` 与 `FuzzReadPacket` 覆盖任意输入不 panic、不越界、不产生无法解析的目标；已收录一个回归语料。
- [x] TCP e2e：Trojan -> Direct -> 本地目标；验证双向 payload 与 tx/rx 计量。
- [x] UDP e2e：Trojan -> Direct -> 多个本地 UDP 目标；验证来源地址、payload 与仅 payload 计量。
- [x] 两跳 e2e：Trojan -> Hysteria2 Node -> 本地 TCP/UDP 目标；验证节点选择不会退化为 direct。
- [x] 验证未授权节点派生凭据被拒绝且不产生流量，以及停用用户的 datagram 被拒绝、不计量并关闭 association。
- [ ] 验证错误凭据、过期用户、超额与下载限速在 Trojan 路径上的行为，并覆盖 SQLite flush 后的持久化结果。
- [x] 运行 `CGO_ENABLED=1 go test ./...`、`go test -race ./...`、`go vet ./...`、`gofmt`。
- [ ] 对未认证握手、空闲已认证连接、并发 relay 与关闭过程做负载测试，确定上限和系统资源消耗。

## 阶段 4：后续，不与当前实现混合

- [ ] 生成 Clash.Meta Trojan 订阅条目，每个用户节点组合独立、名称不冲突，并按已支持的 UDP 能力输出 `udp: true`。
- [ ] 增加管理后台的 Trojan 配置可见性和安全提示；不显示或记录不必要的原始凭据。
- [ ] 评估独立 `access_credentials` 表，以支持每协议独立凭据、单独撤销、轮换与审计。
- [ ] 实现 Trojan fallback，使认证失败的连接表现为普通网站。契约与验收见 [INBOUND_REFACTOR_REVISED.md](INBOUND_REFACTOR_REVISED.md) 的 TODO-PROBE-01：首包保序回放、短首包超时也要回落、各种失败对外不可区分、ALPN 策略、无归属流量的独立上限与脱敏日志、固定后端。Hy2 入站的 `masquerade` 已实现，但它只覆盖 UDP 端口上的 HTTP/3 探测，不改变 Trojan TCP 端口的行为。
- [ ] 若确有部署需求，再单独设计 mux 及 SNI 多路复用（同 TCP 端口共存真实 HTTPS 站点）及其对 fail-closed 策略的影响。
