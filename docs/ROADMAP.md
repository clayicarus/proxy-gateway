# Hy2-Gateway Roadmap

## Phase 1：核心功能（MVP） ✅

- [x] 项目骨架搭建
- [x] 配置解析与校验
- [x] 用户鉴权模块（username:password）
- [x] 按用户路由引擎（EventLogger 桥接方案）
- [x] 出站实现：Direct / SOCKS5 / HTTP CONNECT
- [x] Hysteria2 客户端出站（gateway → 远端 hy2 node 转发）
- [x] 流量统计与配额限制
- [x] SQLite 流量统计持久化（增量日志 + 累计汇总）
- [x] 管理 API（流量查询/重置/健康检查）
- [x] 对接 Hysteria2 核心库，接口类型适配（编译时类型检查）
- [x] 单元测试（auth / config / router / traffic / storage）
- [x] 端到端集成测试（组件级完整请求链路）
- [x] 真实 hy2 客户端 → gateway → 出站 连通测试
- [x] 架构设计文档 & 集成指南

## Phase 2：存储与出站优化

- [ ] traffic_logs 定时聚合：超过 N 天的明细按天合并为汇总记录，删除原始明细
- [ ] flush 间隔可配置化，支持更大间隔（如 60s / 5min）减少写入量
- [ ] 出站健康检查与自动故障切换
- [ ] 出站连接池复用，减少握手开销
- [ ] 支持按域名/IP 规则做二级路由（ACL 与用户路由结合）

## Phase 3：用户管理增强

- [ ] 外部 HTTP 认证后端（对接已有用户系统）
- [ ] 用户动态增删（API 热更新，无需重启）
- [ ] 配置文件热重载（SIGHUP 信号）
- [ ] 用户连接数限制（同时在线设备数）
- [ ] 用户有效期管理（到期自动禁用）

## Phase 4：可观测性

- [ ] Prometheus metrics 导出（流量、连接数、延迟）
- [ ] Grafana 仪表盘模板
- [ ] 结构化日志优化（按级别输出，日志轮转）
- [ ] 连接级别 tracing（排查单用户问题）

## Phase 5：运维与部署

- [ ] systemd service 文件
- [ ] Docker Compose 一键部署（含 Prometheus + Grafana）
- [ ] 多实例部署方案（共享用户数据库）
- [ ] 自动化 TLS 证书管理（ACME 集成）
- [ ] 平滑重启（graceful shutdown，不断开现有连接）

## Phase 6：高级特性

- [ ] Web 管理面板（用户管理、流量可视化、节点状态）
- [ ] 按用户限速（令牌桶/漏桶算法）
- [ ] 审计日志（记录用户访问的域名，可选开启）
- [ ] 多入站协议支持（在同一个 gateway 上同时支持 hy2 + 其他协议）
- [ ] 插件机制（允许第三方扩展认证、路由、出站逻辑）
