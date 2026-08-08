# 管理后台与运行时配置设计

## 目标

本设计将 Gateway 从静态用户/节点 YAML 配置迁移为 SQLite 驱动的运行时控制面，提供仅本地访问的管理后台、公开订阅端点、月度流量计量和 systemd 集成。

Gateway 仍是一个单进程服务：QUIC Gateway、本地管理 Web、订阅服务和调度器都运行在同一二进制内。systemd 负责进程生命周期、崩溃恢复和 watchdog；应用不 fork 或监督自己的子进程。

## 配置边界

YAML 仅保存无法安全或合理地存入运行时数据库的启动配置：

- Gateway UDP 监听、TLS 证书文件、QUIC、混淆和伪装参数。
- SQLite 路径、流量 flush 间隔和自然月时区。
- 本地管理 Web 监听地址，必须为 loopback 地址。
- 订阅端点监听地址、对外 Gateway 地址、SNI 和订阅迁移密钥。
- systemd unit 名称和 watchdog 开关。

用户、节点、用户节点授权、到期时间、限额、限速和订阅 token 都存入 SQLite。`users`、`nodes` 和服务端 `fallback` 不再是正常运行配置。

## 数据模型

SQLite 增加以下逻辑实体：

- `managed_users`：用户名、密码、软删除时间、到期时间、每月总流量额度（tx + rx）、下载总限速（rx）、订阅 token 哈希、创建/更新时间。
- `managed_nodes`：节点名、显示名、类型、序列化配置、启用状态、创建/更新时间。`direct` 是内置路由，不进入该表。
- `user_nodes`：用户到节点（或 `direct`）的多对多授权。
- `config_state`：当前保存 revision、当前 Gateway 进程成功加载的 revision、待重启状态。
- `restart_jobs`：一次性、持久化的计划重启任务。
- `process_runs`：每次进程运行、systemd 退出结果、退出码、触发来源与配置 revision。

流量明细保留 `user_id`、`node_id`、`tx_bytes`、`rx_bytes` 与 UTC Unix 时间。启动迁移会将旧版带时区的文本时间规范化为 UTC Unix 秒。月度查询按 YAML `timezone` 计算边界。用户套餐用量为当前自然月内所有节点的 `tx + rx` 之和；用户下载限速只限制 `rx`，且所有连接共享额度。

## 认证、到期和流量

认证在内存用户快照上进行。后台修改用户的删除状态、到期时间、月额度、下载限速和密码后，Gateway 最迟在 2 秒刷新周期后应用该快照。节点和用户节点授权只在完整重启后重新加载。

- 后台“停用用户”通过软删除标记实现；重新启用会清除该标记，不丢失配置与历史流量。
- 流量额度超额：产生下一笔流量时立即断开整个客户端连接。
- 用户停用或到期：拒绝新连接；已有 QUIC 会话在产生下一笔流量时立即断开。
- 到期时间当前由管理员直接编辑 `expires_at`；清空表示不过期。数据库统一保存 UTC Unix 秒，表单按 YAML `timezone` 解释。
- 节点错误直接返回给客户端；不提供服务端隐式 fallback。

## 订阅

新用户生成随机的 16 位 Base62 bearer token。数据库只存 SHA-256 哈希，订阅请求以哈希索引用户，支持单用户重置链接。

旧版本 token 为 `Base62(HMAC-SHA256(subscriptionSecret, username)[:12])`。`migrate` 命令读取旧 YAML 的 `sub.secret`，若为空则读取 `api.secret`，计算旧 token 并存储其哈希，因此已发布订阅 URL 保持可用。

订阅端点仅为有效、未软删除、且已由当前 Gateway 进程加载的用户提供配置。订阅中的节点和用户节点授权使用 Gateway 启动快照，避免待重启配置提前下发；密码、到期和软删除状态实时读取。订阅中列出用户获授权的多个节点，客户端可自行选择或故障切换；Gateway 不会改变客户端选择的节点。

## 管理 Web 与 CSRF

管理 Web 使用服务端渲染的 HTML 表单，不提供通用 JSON 管理 API。它仅监听 loopback。所有写操作要求启动时生成的 CSRF token；为兼容 SSH 转发和本地代理访问，不校验 `Origin`/`Referer`。这不是登录鉴权。

用户策略保存、密码重置、订阅链接重置、用户停用/启用、节点停用和 Gateway 重启均要求二次确认。确认框必须说明凭据失效范围、现有连接是否中断、配置是否保留以及是否需要重启；确认只属于前端防误操作措施，后端仍以 CSRF token 作为写请求保护。

后台采用左侧板块导航，划分为基本信息、用户管理、活跃连接、成本分析和故障分析。页面显示用户、流量、按节点的 Gateway/Node 成本估算、节点与授权、待重启 revision、计划重启和进程运行历史。

管理页面通过同一 loopback 监听器上的只读 `/live` 端点每两秒获取内存累计计数，并在浏览器中按相邻采样差计算当前 `tx`/`rx` 速度。该端点同时返回当前客户端 IP、源端口、用户、所选节点以及活跃 TCP/UDP 请求目标。连接明细只保存在进程内存，不写入 SQLite，断开或进程重启后清除。

成本表格可在浏览器中按列排序。只读 `/traffic-range` 端点按 YAML `timezone` 解释管理页面提交的起止时间，以 UTC 边界查询 SQLite，并返回用户、节点与 UTC 小时聚合；页面将小时桶转换到配置时区，用于定位所选范围内的小时流量峰值。查询范围最大为 366 天，执行查询前会先 flush 当前内存流量。

`/live` 与 `/traffic-range` 仅服务本地管理页面，不提供管理写操作，也不对公网订阅监听器开放。进程重启或累计计数回退时，实时速度重新建立采样基线。

成本术语如下，均为有效负载估算，不含 QUIC/IP 包头与重传：

- 用户上传 `tx`：客户端到 Gateway 后转发给 Node/目标。
- 用户下载 `rx`：Node/目标到 Gateway 后转发给客户端。
- Gateway 经节点的估算出站：`tx + rx`。
- Node 的估算出站：`tx + rx`。
- `direct` 仅在 Gateway 侧计入 `tx + rx`。

## YAML 迁移

迁移是一次性显式命令：

```text
hy2-gateway migrate -c legacy-gateway.yaml
```

命令在单一事务中校验并导入旧 YAML 用户、节点和授权，丢弃服务端 fallback，计算旧订阅 token，并设置迁移标记。目标数据库已有管理数据时命令失败，不覆盖运行配置。迁移后正常 YAML 删除 `users` 与 `nodes`。

恢复错误的管理用户配置时可显式执行 `migrate --replace-users -c legacy-gateway.yaml`。该事务只清空并重建 `managed_users` 与 `user_nodes`，保留节点和全部运行、流量历史；YAML 引用的非 `direct` 节点必须已存在于 `managed_nodes`。普通 `migrate` 仍拒绝覆盖，防止误操作。

## systemd、重启与 watchdog

systemd 直接执行 Gateway。推荐的 service 配置包括 `Restart=on-failure`、重启退避、启动失败上限、`TimeoutStopSec`、`KillMode=control-group` 和 `WatchdogSec`。

Gateway 在启动、退出和健康检查状态变化时记录运行事件。systemd 通过 `ExecStopPost` 调用同一二进制的轻量 `record-exit` 子命令，写入 `SERVICE_RESULT`、`EXIT_CODE` 和 `EXIT_STATUS`。后台据此展示人工重启、定时重启、watchdog、OOM、信号、异常退出和启动限流。

watchdog 在 Gateway 启动后才进入就绪状态，并在 Gateway 服务循环仍在运行且 SQLite 健康检查成功时发送心跳。出站 Node 不可用只标记节点问题，不触发整个 Gateway 重启。

节点/授权改动增加保存 revision 并标记待重启。Gateway 成功启动并加载数据库配置后写入运行 revision。立即或定时重启任务通过受限 systemd D-Bus 权限请求重启 `hy2-gateway.service`；后台不拼接 shell 命令。

收到 SIGTERM 时，Gateway 停止接受新连接、关闭 HTTP 服务、停止 QUIC 服务、flush 流量、关闭出站连接与 SQLite，再退出。systemd 在宽限时间后才强制终止。
