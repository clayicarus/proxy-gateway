# Hy2-Gateway Roadmap

本文只记录当前实现状态和仍可能开展的工作。设计约束以 `ARCHITECTURE.md` 和 `ADMIN_DESIGN.md` 为准。

## 已完成

- [x] Hysteria2 Gateway 入口与 Direct、SOCKS5、HTTP CONNECT、Hysteria2 出站
- [x] `username:node:password` 认证和显式多节点授权
- [x] fail-closed 路由，不提供服务端隐式 fallback
- [x] SQLite 用户、节点、授权、token、流量、revision、重启和进程历史
- [x] 旧 YAML `migrate` 与 `migrate --replace-users`
- [x] 用户软删除、到期、密码重置和订阅 token 重置
- [x] 按配置时区的自然月 `tx + rx` 配额
- [x] 用户总下载限速和超额/到期/停用连接关闭
- [x] 本地管理 Web 与 CSRF 防护
- [x] 基本信息、用户管理、活跃连接、成本分析和故障分析页面
- [x] 实时速度、可排序成本表和最长 366 天的范围流量查询
- [x] 独立公开订阅服务和 Clash.Meta 配置生成
- [x] 配置 revision、立即/定时 systemd 重启与退出原因记录
- [x] systemd watchdog 和优雅停机
- [x] 单元、集成、真实 Hysteria2 链路和路由并发测试

## 近期候选

- [ ] 流量明细保留策略：把历史 `traffic_logs` 聚合为日桶并删除过细记录
- [ ] 数据库备份、恢复和完整性检查操作手册
- [ ] 审计日志：记录管理员写操作，不记录用户明文密码或订阅 token
- [ ] 用户并发连接数或设备数限制
- [ ] 节点健康状态与拨号错误摘要，仅用于诊断，不触发服务端 fallback
- [ ] 管理后台大数据量分页和查询基准，重点覆盖低内存服务器
- [ ] Prometheus 指标与可选 Grafana 模板
- [ ] 日志轮转和敏感字段脱敏检查

## 中长期候选

- [ ] 节点和授权安全热加载，包括旧连接释放策略和原子快照切换
- [ ] 多 Gateway 实例部署方案；当前 SQLite 控制面按单进程设计
- [ ] 外部认证或用户系统集成
- [ ] Docker Compose 部署模板和容器环境下的独立进程监督方案
- [ ] 平滑升级方案；当前优雅停机会关闭现有连接并由客户端重连
- [ ] 外部 ACME 工具自动续期后的受控重启流程
- [ ] 订阅 DNS 策略模板和更多客户端格式

## 明确不做

- 服务端自动选择备用节点或回退到 `direct`。多节点选择和故障切换属于客户端订阅与路由策略。
- 通过公网暴露无鉴权的管理后台。当前后台只允许 loopback，并通过 SSH 转发访问。
- 在正常运行 YAML 中继续维护用户和节点。旧字段只用于一次性迁移。
