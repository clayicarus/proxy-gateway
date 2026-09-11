# Trojan 入站 TODO

本清单对应 [Trojan 入站设计](TROJAN_INBOUND_DESIGN.md)。完成标准是 TCP CONNECT 与 UDP ASSOCIATE 在身份、路由、流量与生命周期上与现有 Hy2 行为一致，而不是仅能建立一个 Trojan 连接。

勾选项表示仓库内已有实现和对应测试。未勾选项仍是缺口，不因架构就绪而视为完成。

## 阶段 0：先锁定契约

- [x] 确认支持 TCP CONNECT、UDP ASSOCIATE 和可选网站 fallback；BIND、mux 等非标准命令不进入代理路径，启用 fallback 时按非法初始请求回退。
- [x] fallback 判定遵循 [Trojan 官方协议](https://github.com/trojan-gfw/trojan/blob/3e7bb9aecdc694f9bcae8d646fae395f773d60f8/docs/protocol.md#L49)：完整请求结构与凭据必须同时有效；任何初始请求格式错误都回退，即使其中的凭据正确。
- [x] 确认 Trojan 原始 password 固定为 `username:node:password`，每个用户节点组合独立。
- [x] 确定订阅契约：单入口使用 `sub.inbound`，多入口使用 `sub.endpoints[]`，分别配置 `serverAddr`、`sni` 和 `insecure`。
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
- [x] 精确解析 `SHA224(password) + CRLF + 命令 + address + port + CRLF`，按官方规则将截断、未知 ATYP、空域名、错误分隔符和不支持的命令判为非法结构。CONNECT 零端口、域名字符等本地目标限制单独校验，不能将结构完整且凭据有效的请求送入 fallback。
- [x] 通过 `Kernel.AuthenticateTrojan` 取得私有 session，再由 `Kernel.OpenTCP` 选择出站；adapter 拿不到路由 ID 或裸 outbound。
- [x] 实现双向计量 TCP relay；准入返回 false 时关闭两端且不再转发。
- [x] 实现 UDP ASSOCIATE：`Kernel.OpenUDP` 打开出站 flow，逐 datagram 分帧、准入与转发，空闲回收，单包失败只丢包。
- [x] 认证成功后维护在线状态、`Tracker` 会话与 TCP/UDP request 状态；所有退出路径恰好清理一次。
- [x] 服务错误纳入 `inbound.Manager` 的启停与错误路径；停机时停止 accept、关闭活动连接与出站 flow 并等待 goroutine 退出。

## 阶段 3：测试与验收

- [x] 单元测试 SHA-224 索引、热刷新、哈希格式和用户节点映射。
- [x] 表驱动解析测试：IPv4、IPv6、最长域名、截断首包、错误 CRLF、错误命令；区分非法请求结构与零端口、非法域名字符等本地目标拒绝。
- [x] 表驱动 UDP 分帧测试：往返编码、逐包边界、零端口、错误 CRLF、超出缓冲的长度、截断 payload。
- [x] `FuzzReadRequest` 与 `FuzzReadPacket` 覆盖任意输入不 panic、不越界、不产生无法解析的目标；已收录一个回归语料。
- [x] TCP e2e：Trojan -> Direct -> 本地目标；验证双向 payload 与 tx/rx 计量。
- [x] UDP e2e：Trojan -> Direct -> 多个本地 UDP 目标；验证来源地址、payload 与仅 payload 计量。
- [x] 两跳 e2e：Trojan -> Hysteria2 Node -> 本地 TCP/UDP 目标；验证节点选择不会退化为 direct。
- [x] 验证未授权节点派生凭据被拒绝且不产生流量，以及停用用户的 datagram 被拒绝、不计量并关闭 association。
- [ ] 验证错误凭据、过期用户、超额与下载限速在 Trojan 路径上的行为，并覆盖 SQLite flush 后的持久化结果。
- [x] 运行 `CGO_ENABLED=1 go test ./...`、`go test -race ./...`、`go vet ./...`、`gofmt`。
- [ ] 对未认证握手、空闲已认证连接、并发 relay 与关闭过程做负载测试，确定上限和系统资源消耗。

## 阶段 4：订阅与后续

- [x] 生成 Clash.Meta Trojan 订阅条目，每个用户节点组合独立、名称不冲突，并按已支持的 UDP 能力输出 `udp: true`；验证运行时配置到 HTTP 订阅再到 TCP/UDP 转发的完整路径。
- [ ] 增加管理后台的 Trojan 配置可见性和安全提示；不显示或记录不必要的原始凭据。
- [ ] 评估独立 `access_credentials` 表，以支持每协议独立凭据、单独撤销、轮换与审计。
- [x] 按官方规则完成 Trojan 网站 fallback：完整初始请求结构和凭据共同判定；错误命令、地址、分隔符以及截断/超时均回退，包括正确凭据后出现的格式错误。回放全部已消费首部及未读流，首部最多 320 字节；完整首部校验前不创建代理 session。`probeTimeout` 覆盖整个首部，并保留固定后端、独立资源上限、脱敏日志和完整停机。契约与验收见 [INBOUND_REFACTOR_REVISED.md](INBOUND_REFACTOR_REVISED.md) 的 TODO-PROBE-01。
- [x] 验证合法 Trojan 请求的目标拨号失败、策略拒绝以及进入代理后的 UDP 分帧错误不会转入 fallback；网站流量不影响用户账本、在线状态或请求追踪。
- [ ] 修复 TODO-PROBE-02（低优先级）：停用或到期用户的有效凭据会被明文回放到 fallback 源站并进入其 access log；只有"凭据不存在"才应回退。
- [ ] 若确有部署需求，再单独设计 mux 及 SNI 多路复用（同 TCP 端口共存真实 HTTPS 站点）及其对 fail-closed 策略的影响。
