# Trojan TCP 入站 TODO

本清单对应 [Trojan TCP 入站设计](TROJAN_INBOUND_DESIGN.md)。完成标准是 TCP CONNECT 与现有 Hy2 在身份、路由、流量与生命周期上的行为一致，而不是仅能建立一个 Trojan 连接。

## 阶段 0：先锁定契约

- [ ] 确认第一期只支持 TCP CONNECT；拒绝 BIND、UDP ASSOCIATE 和 fallback。
- [ ] 确认 Trojan 原始 password 固定为 `username:node:password`，每个用户节点组合独立。
- [ ] 决定第一期是否只提供手工客户端配置；若生成订阅，确认 `trojan.serverAddr`、`trojan.sni`、`trojan.insecure` 的配置语义与部署文档。
- [ ] 明确未认证连接、TLS 握手和首包解析的超时及并发上限，并记录压测依据。

## 阶段 1：配置与身份索引

- [ ] 在 `internal/config` 增加可选 `trojan.listen`，并测试禁用、有效 TCP 地址与冲突地址。
- [ ] 在 `internal/trojan` 实现不可变 `SHA224(raw password) -> id` 索引；仅接受 56 位小写十六进制哈希。
- [ ] 从启动 `users` 快照构建索引，确保 `direct` 也能作为显式授权节点。
- [ ] 扩展用户刷新任务，使其对保留启动 routes 的 `updated` 快照同步更新 Trojan 索引。
- [ ] 测试密码变更、停用、到期、新用户和授权变更的生效边界；后两者重启前必须保持不可用。
- [ ] 确认日志、错误对象、测试失败输出均不泄漏原始 Trojan password 或认证哈希。

## 阶段 2：Trojan TCP 服务

- [ ] 实现独立 TCP listener、TLS `HandshakeContext`、握手/首包 deadline、accept 错误退避与连接追踪。
- [ ] 精确解析 `SHA224(password) + CRLF + CONNECT + address + port + CRLF`，拒绝截断、超长、未知 ATYP、空域名、零端口和额外命令。
- [ ] 通过 `RoutingOutbound.GetOutboundForID` 获取出站并拨号，不能使用 Hysteria2 的事件上下文 channel。
- [ ] 实现双向计量 relay；`LogTraffic` 返回 false 时关闭两端且不会继续转发。
- [ ] 在认证成功后维护 `LogOnlineState`、`Tracker.Connect` 与 TCP request 状态；所有退出路径恰好清理一次。
- [ ] 将 Trojan 服务错误纳入主服务错误通道，并在 SIGTERM 时停止 accept、关闭活动连接、等待 goroutine 后再 flush 流量。

## 阶段 3：测试与验收

- [ ] 单元测试 SHA-224 索引、热刷新、哈希格式和用户节点映射。
- [ ] 对解析器做表驱动测试：IPv4、域名、IPv6、截断首包、错误 CRLF、错误命令、非法端口、超长域名。
- [ ] 添加 fuzz test，确保任意有限输入不会 panic、无限分配或建立出站连接。
- [ ] TCP e2e：Trojan -> Direct -> 本地目标；验证双向 payload、tx/rx、在线状态和 SQLite flush。
- [ ] TCP e2e：Trojan -> Hysteria2 Node -> 本地目标；验证节点选择不会退化为 direct。
- [ ] 验证错误凭据、未授权节点派生凭据、停用、过期、密码重置、超额与下载限速。
- [ ] 运行 `CGO_ENABLED=1 go test ./...`、`go vet ./...`、`git diff --check`；在允许监听 loopback 的环境运行 `go test -race ./...`。
- [ ] 对未认证握手、空闲已认证连接、并发 relay 与关闭过程做负载测试，确定上限和系统资源消耗。

## 阶段 4：第二期，不与 TCP MVP 混合

- [ ] 生成 Clash.Meta Trojan 订阅条目，每个用户节点组合独立、名称不冲突且显式 `udp: false`。
- [ ] 增加管理后台的 Trojan 配置可见性和安全提示；不显示或记录不必要的原始凭据。
- [ ] 设计并实现 Trojan UDP ASSOCIATE，包含 datagram 分帧、会话生命周期、速率限制和 e2e 测试。
- [ ] 评估独立 `access_credentials` 表，以支持每协议独立凭据、单独撤销、轮换与审计。
- [ ] 若确有部署需求，再单独设计 HTTPS fallback / SNI 多路复用及其对 fail-closed 策略的影响。
