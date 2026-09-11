# Trojan TCP 入站设计

## 状态与范围

本文定义并记录 Proxy Gateway 的 Trojan 入站。目标是在不改变现有出站、用户策略、SQLite 流量口径和管理数据模型的前提下，增加标准 Trojan 入站。

已交付 TCP CONNECT、UDP ASSOCIATE、Clash 订阅和可选的 HTTPS 网站回退。BIND、mux 和 Trojan 专用数据库凭据仍不支持。Gateway 继续坚持客户端显式选择节点、服务端不自动切换节点或回退到 `direct`。

## 已确认的约束

- Hysteria2 继续监听 UDP；Trojan 监听 TCP。因此两个入站可同用数值端口，例如 UDP `:443` 与 TCP `:443`。Trojan UDP ASSOCIATE 同样在这条 TCP/TLS 连接内传输，不额外监听 UDP。
- Trojan 在 TLS 内只提交固定的 `SHA224(password)`，服务端不能从哈希中反解用户或节点。
- 每条 Trojan 凭据绑定一个确定的 `username:node`。一个用户有多个授权节点时，客户端需要使用多个 Trojan 代理条目选择节点。
- 默认认证失败即关闭；配置 `trojan.fallback` 后，TLS 成功但无有效凭据的连接会回退到固定 HTTP/1.1 源站。已认证但命令不支持时仍关闭。Hysteria2 的 `masquerade` 独立覆盖 UDP 上的 HTTP/3，两者可使用同一网站后端。
- 现有节点和授权仍以启动快照为准，保存后必须重启；密码、停用、到期、额度和限速仍在约两秒内刷新。

## 配置契约

在 `inbounds` 中新增 `type: trojan` 项；未配置该项时不启用 Trojan。

```yaml
inbounds:
  - name: trojan-public
    type: trojan
    listen: ":443"                       # TCP/TLS inbound
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 256
      udpIdleTimeout: 60s
```

入站 TLS 始终复用顶层 `tls.cert`、`tls.key`。Trojan 可以与 Hysteria2 共用数值端口，因为二者分别监听 TCP 和 UDP。

`udpIdleTimeout` 只回收双向都没有 datagram 的 UDP association，默认 60s，不是 TCP CONNECT 的空闲超时。

订阅通过 `sub.inbound` 选择单个入口，或通过 `sub.endpoints[]` 发布多个入口。每项的 `serverAddr`、`sni` 与 `insecure` 只影响生成的客户端配置，服务端仍使用顶层 TLS 证书。公网地址必须显式提供，不能从 `inbounds[].listen` 推断。完整示例见 [gateway-mixed.yaml](../configs/gateway-mixed.yaml)。

## 凭据与身份映射

不增加数据表。对启动用户快照中的每个授权 `(username, node)`，构造：

```text
raw password = username + ":" + node + ":" + user.password
lookup key   = lowercase_hex(SHA224(raw password))
value        = id = username + ":" + node
```

用户与节点名称已经禁止冒号，密码允许冒号，因此拼接是无歧义的。索引只保存协议要求的 56 字符 SHA-224 十六进制串和 `id`，不额外持久化或记录原始 Trojan 密码。

共享 `auth.Authenticator` 持有 Trojan 的 SHA-224 凭据索引和 Hy2 用户策略。启动时从同一份 `users` 快照构造；现有两秒刷新任务构造保留启动 routes 的 `updated` 用户视图后，原子替换两种协议共用的认证快照。索引不原地修改。

这样保证：

- 密码重置会在下一次刷新后同时吊销所有该用户的 Hy2 与 Trojan 凭据。
- 停用、到期会在下一次刷新后拒绝新的 Trojan 连接。
- 新用户、新授权或节点删除在重启前不会提前进入 Trojan 索引。
- 一个静态 Trojan 密码是 bearer credential；数据库已有用户密码明文的风险模型不因本期而改善。独立、可单独撤销的 Trojan 密码是后续 `access_credentials` 表的目标。

认证匹配前必须检查收到的值恰为 56 个小写 ASCII 十六进制字符；不要接受可变长度输入、前后空白或无界 `ReadString`。哈希不命中和状态不允许均只关闭连接，日志不得包含原始密码或认证哈希。

## 入站状态机

```text
TCP accept
  -> TLS HandshakeContext（握手 deadline）
  -> 精确读取 SHA224(password) + CRLF
  -> 凭据索引查找，得到 Kernel 签发的私有 session
  -> 读取 command + SOCKS 风格目标地址 + CRLF
  -> CONNECT (0x01)        -> Kernel.OpenTCP(target) -> 双向计量 relay
  -> UDP ASSOCIATE (0x03)  -> Kernel.OpenUDP()       -> 逐包计量 relay
  -> 关闭两端、更新在线状态与活跃连接
```

`BIND (0x02)` 和其他命令一律拒绝；不能静默把未支持的命令当 CONNECT，或返回伪造成功响应。Trojan 没有单独的认证成功/CONNECT 成功帧，拨号成功后直接开始双向传输；拨号失败则关闭连接。

地址解析必须固定长度读取：IPv4 4 字节、IPv6 16 字节、域名为 1 字节长度加最多 255 字节。CONNECT 的端口必须非零；域名不能为空，且不得包含控制字符或会破坏 `host:port` 还原的字符（`:`、`[`、`]`、`/`、`\`、`?`、`#`、`@`、`%`、NUL）。最终目标用 `net.JoinHostPort` 规范化，避免 IPv6 拼接错误。

## UDP ASSOCIATE

请求头中的地址对 UDP 只是名义值，标准客户端常发送未指定地址和端口 0，因此它不参与路由；每个 datagram 自带目标。握手之后，连接内是连续的 Trojan UDP 包：

```text
ATYP(1) + DST.ADDR + DST.PORT(2) + Length(2) + CRLF + Payload(Length)
```

服务端回程包使用同一格式，地址是 datagram 的实际来源。约束：

- 一条 association 对应一个出站 UDP flow（`Kernel.OpenUDP`），由已授权 node 决定路径；`direct` 与远端 Hysteria2 node 走同一条代码路径。
- Length 上限由 2 字节前缀决定（65535），读取缓冲同样按此上限固定；超过缓冲的长度直接判为非法包并结束 association，不做分块拼接。
- 每个 datagram 在写出前调用一次账务准入：上行按 payload 长度计 `tx`，下行按 payload 长度计 `rx`。Trojan 的地址、长度和 CRLF 分帧不计入用户流量，与现有 payload 口径一致。
- 准入被拒绝时该 datagram 不转发，并关闭整条 association；这与 Hy2 的“策略拒绝作用于整个会话”一致。
- 单个 datagram 的目标不可解析或发送失败只丢该包，不结束 association；出站 flow 被关闭才结束。已准入的字节不退款。
- `udpIdleTimeout` 内双向都没有 datagram 时回收 association。客户端断开、Gateway 停机和 `Close` 都会取消双向 relay 并关闭出站 flow；`Wait` 覆盖两个方向和空闲看门狗。
- 管理后台把 association 显示为一条 `UDP` 请求，与 Hy2 的 UDP 请求展示口径相同。

## 复用路径

认证成功后不经过 Hysteria2 特有的回调，而是由 adapter 获得 Kernel 签发的私有 session，并显式调用：

```go
session, ok := kernel.AuthenticateTrojan(inbound, clientAddr, credential)
targetConn, err := kernel.OpenTCP(ctx, session, target)
```

这仍会使用同一个 `OutboundFactory`，因此 Direct TCP timeout、远端 Hysteria2 节点状态、预热、DNS 刷新和后台重连全部保持一致。adapter 无法构造路由 ID 或取得裸 outbound，因此不需要修改路由数据模型或 SQLite 表。

成功认证后调用：

```text
trafficLogger.LogOnlineState(id, true)
connectionTracker.Connect(clientAddr, id)
connectionTracker.StartTCP(clientAddr, target)
```

无论拨号、转发或关闭发生何种错误，清理路径必须恰好调用一次对应的 `StopTCP`、`Disconnect` 和 `LogOnlineState(id, false)`。认证失败或拨号前失败不得增加在线数。

## 流量、配额与限速

已认证代理请求的双向 relay 不可直接使用两个裸 `io.Copy`。每次有效负载读取后都必须经计量包装器：

```text
client -> target: TrafficLogger.LogTraffic(id, n, 0)
target -> client: TrafficLogger.LogTraffic(id, 0, n)
```

现有 `TrafficLogger` 因而继续负责：按 `user:node` 写入 SQLite、跨节点的自然月 `tx + rx` 额度、跨全部连接的用户下载限速，以及停用/到期/超额时返回 `false`。返回 `false` 时 relay 必须用 `sync.Once` 关闭两个连接，防止另一方向继续转发。

UDP association 使用同一账本，按 datagram 而不是按 chunk 准入：上行在 `WriteTo` 之前、下行在写回客户端之前各调用一次。

计量只涵盖 relay 的应用有效负载，不计 Trojan 认证、命令、地址和分帧头（包括 UDP 每包的地址与长度前缀）。实现须锁定并测试当前语义：超额触发的 chunk 不再继续写出；因对端写入失败造成的部分写入如何计量必须与现有 Hy2 口径一致并在测试中固定，不能在两个入站间产生无说明的差异。

## TLS、资源与停机

- TCP listener 启动时同步绑定；绑定失败和 accept loop 异常都进入现有 `serviceErrCh`，使 systemd 以失败状态恢复进程。
- 每个连接在 TLS handshake 和 Trojan 首包解析期间设置短 deadline，成功解析后清除 deadline。该 deadline 是防 Slowloris 的必要边界，不是空闲会话超时策略。
- 限制并发握手/未认证连接数，并确保 accept 错误采用退避，避免文件描述符耗尽或忙循环。具体阈值应配置化或先以保守常量实现，并在压测后确定。
- `Service.Close` 必须停止 accept、关闭所有已认证与握手中的连接及其出站 TCP 连接和 UDP flow，并等待其 goroutine 退出；主进程必须在最终 flush 前完成该步骤，避免关闭后的 relay 丢失最终计量。
- 网站回退显式配置后才启用，并纳入相同的连接注册表及 `Close`/`Wait`。SNI 多路复用不在当前范围，网站后端始终由配置固定。

## HTTPS 网站回退

`trojan.fallback.addr` 指向固定明文 HTTP/1.1 源站。TLS 在 Trojan listener 终止，只声明 `http/1.1` ALPN；不选择客户端请求中的 Host/SNI 作为目标，不建立用户代理 session，也不进入用户账本、额度和限速路径。

凭据读取通过有界 tee 保留最多 58 字节，包括 EOF 和超时前的部分读取。未知凭据、格式错误与短首包统一等到 `probeTimeout` 窗口结束，再通过 `io.MultiReader` 回放已消费字节并继续转发未读流。有效凭据恢复原有的请求解析 deadline，非法命令仍关闭。网站回放保留客户端的写半关闭，以允许源站在请求发送完毕后返回响应。

独立 `maxConnections` 覆盖分类等待与后端 relay；在释放握手槽位前取得网站槽位，防止创建无界等待连接。`dialTimeout` 限制拨号，`timeout` 限制判定结束后拨号与转发的总时长；根 context 取消立即中断等待和连接。后端登记到现有 registry，双向 relay 完全退出后才释放 handler。诊断仅记录事件与入口名，不记录首包、疑似凭据、请求路径或原始 TLS 错误。

默认值和部署方式见 [部署指南](DEPLOYMENT.md)。配置与单元测试覆盖短请求、超时后续读、错误凭据、准确回放、固定目标、半关闭、容量限制、有效客户端隔离、后端故障和停机。端到端测试使用完整运行时配置，验证 HTTPS/HTTP3 网站、通过网站入口取得订阅，以及按订阅配置完成 Hysteria2 TCP、Trojan TCP/UDP。

## 订阅与管理后台

订阅复用 SQLite 用户、密码、订阅 token 与启动时的节点授权快照。管理后台生成的同一个订阅 URL 可以提供 Hysteria2、Trojan 或混合配置；已有单 Hysteria2 订阅配置继续可用。

每个已授权节点与每个公开 Trojan 入口生成独立代理：`type: trojan`、该入口的 `server`/`port`、原始 `username:node:password`、TLS `sni` 和 `skip-cert-verify`，并按已支持的 UDP ASSOCIATE 输出 `udp: true`。Trojan 和混合订阅的代理名称带协议后缀；同协议多个入口再加入口名称，重复别名自动消歧。客户端选择组包含所有生成的代理。`direct` 授权条目使用相同的入口和 TLS 规则，客户端本地 `DIRECT` 仍是独立选项。

密码与用户状态实时读取，token 重置立即失效；新增用户和节点授权仍需重启后生效。订阅包含客户端凭据，响应设置 `Cache-Control: no-store`。启用网站回退的 Trojan 入口额外输出 `alpn: [http/1.1]`，其他入口不受影响。配置测试覆盖单 Trojan、混合入口、IPv6、未知或重复入口、端口和通配地址；API 测试覆盖授权快照、密码与 token 更新、名称冲突和 TLS 参数，端到端测试从运行时 YAML 和 HTTP 订阅实际建立 Hysteria2 TCP、Trojan TCP 与 UDP 连接。

## 非目标与后续

- Trojan BIND、mux 和基于 SNI 的多站点复用不在当前范围。
- 不引入服务端节点自动选择或 fallback。
- 不修改现有 Hy2 wire protocol、认证格式、出站协议、SQLite 流量 schema 或用户授权模型。
- 需要独立 Trojan 凭据、按协议撤销和审计时，新增 `access_credentials` 表，而非继续扩展派生密码规则。
