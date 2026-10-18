[English](README.md) | **中文**

# Proxy Gateway

支持 Hysteria2 与 Trojan 的多用户代理网关，在一台服务器上统一管理用户、出站节点、订阅和流量额度。用户通过客户端选择获授权的节点，Gateway 负责认证、路由和流量策略。

## 能做什么

### 流量入口与出口转发

- **入口**：Hysteria2 和 [Trojan](docs/TROJAN_INBOUND_DESIGN.md)，支持 TCP 与 UDP 代理。
- **出口**：转发到远端 Hysteria2 节点，或通过 Gateway 的 `direct` 直连目标。
- **流量策略**：校验用户及节点权限，执行到期、自然月额度和用户总下载限速。
- **节点恢复**：后台自动重连不可用节点；客户端负责节点选择与故障切换。
- **网站服务**：可选提供 Hysteria2 HTTP/3 网站伪装和 Trojan HTTPS 网站回退。

流量按经过 Gateway 的上下行有效负载统计，包含 Gateway 的 `direct`，不含客户端本地 `DIRECT`、QUIC/IP 包头和重传。转发链路见 [架构设计](docs/ARCHITECTURE.md)，Hysteria2 对接方式见 [核心库集成说明](docs/INTEGRATION.md)。

### 管理后台

- **用户**：创建、停用或启用用户，重置密码与订阅链接，设置到期时间、月额度和下载限速。
- **节点与授权**：维护节点配置、启用状态和别名，分配用户节点权限，创建用户时支持全选节点。
- **订阅**：生成 Clash.Meta / Mihomo 混合协议订阅，展示本月用量、流量上限和到期信息。
- **监控**：查看活跃连接、实时速度、流量统计、成本估算和节点运行状态。
- **运维**：查看配置生效状态、进程退出记录，安排立即或定时 systemd 重启。

用户和节点配置保存在 SQLite 中，配置生效规则与订阅行为见 [管理后台说明](docs/ADMIN_DESIGN.md)。

## 如何开始

### 1. 获取程序

从 [Releases](https://github.com/clayicarus/proxy-gateway/releases) 下载对应架构的 Linux amd64 或 arm64 压缩包，校验同一版本的 `SHA256SUMS` 后解压。发布包提供静态 `proxy-gateway` 二进制和示例配置；主机需要 CA 证书与时区数据。

也可以从源码构建，需要 Go 1.24+ 和 C 编译器：

```bash
git clone https://github.com/clayicarus/proxy-gateway.git
cd proxy-gateway
CGO_ENABLED=1 go build -ldflags "-s -w" -o proxy-gateway ./cmd/gateway
```

### 2. 配置并启动

准备域名、TLS 证书及私钥，然后复制 [基础配置](configs/gateway.yaml)：

```bash
cp configs/gateway.yaml gateway.yaml
```

编辑 `gateway.yaml`：

- `tls.cert`、`tls.key`：证书与私钥路径，运行用户必须可读。
- `inbounds`：客户端连接入口，默认示例使用 Hysteria2 UDP `8443`。
- `sub.serverAddr`、`sub.sni`：客户端实际连接的公网域名、端口和证书域名。
- `sub.publicURL`：对外发布的订阅链接前缀，例如 `https://sub.example.com/sub/`。
- `dbPath`、`timezone`：可写的数据库路径与流量结算时区。

启动：

```bash
./proxy-gateway -c gateway.yaml
```

同时启用两种入站可参考 [混合协议配置](configs/gateway-mixed.yaml)，网站伪装与回退可参考 [网站配置](configs/gateway-website.yaml)。

### 3. 创建用户并连接

管理后台没有登录认证，只监听 loopback。从本地电脑通过 SSH 转发访问：

```bash
ssh -N -L 9090:127.0.0.1:9090 user@gateway.example.com
```

打开 `http://127.0.0.1:9090`，添加出站节点、创建用户并授予节点权限，也可以先授权 `direct` 使用 Gateway 直连。节点和授权变更需要重启 Gateway 后生效。

创建用户时保存密码和订阅链接，它们仅在创建或对应重置时展示。按下方部署说明发布订阅服务后，将链接导入支持 Hysteria2 / Trojan 的 Clash.Meta / Mihomo 客户端，选择节点即可连接。

## 如何部署

推荐在 Linux 上使用 systemd 托管，支持 watchdog 和优雅停机：

1. 将程序安装到 `/usr/local/bin/proxy-gateway`，配置放到 `/etc/proxy-gateway/gateway.yaml`。
2. 使用独立服务用户，为证书配置读取权限，为 `/var/lib/proxy-gateway/` 配置写入权限，并将 `dbPath` 设为该目录下的绝对路径。
3. 按 [systemd 部署步骤](docs/DEPLOYMENT.md#4-systemd-部署) 创建服务用户和 systemd 单元，然后启动服务：

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now proxy-gateway.service
   sudo journalctl -u proxy-gateway.service -f
   ```

4. 放行实际使用的入站端口：Hysteria2 使用 UDP，Trojan 使用 TCP，两者可以使用同一数值端口。
5. 按 [订阅发布步骤](docs/DEPLOYMENT.md#7-发布订阅服务) 使用 HTTPS 反向代理将 `/sub/` 转发到 `127.0.0.1:9091`，并使公网地址与 `sub.publicURL` 一致。后台 `9090` 仅通过 SSH 访问。

Trojan 若占用 TCP `443`，独立的订阅 HTTPS 服务需使用其他地址或端口，或采用网站配置中的回退方案。systemd 单元、后台重启权限、订阅反向代理与旧配置迁移步骤见 [部署指南](docs/DEPLOYMENT.md)。

## 致谢

- [Hysteria](https://github.com/apernet/hysteria)：Hysteria2 协议及核心实现。
- [quic-go](https://github.com/quic-go/quic-go) 及其 [apernet 分支](https://github.com/apernet/quic-go)：QUIC 支持。
- [Trojan](https://github.com/trojan-gfw/trojan)：Trojan 协议设计与规范。
- [SQLite](https://www.sqlite.org/) 和 [go-sqlite3](https://github.com/mattn/go-sqlite3)：数据存储。
- [Lucide](https://lucide.dev/)：管理后台图标。

项目使用基于 Hysteria core v2.8.1 的仓库内补丁，保持 Hysteria2 wire protocol 兼容。

## 许可证

本项目采用 **MIT** 许可证。第三方依赖遵循各自的许可证；仓库内 Hysteria core 的版权及许可声明见 [LICENSE.md](third_party/hysteria-core/LICENSE.md)，Lucide 图标采用 ISC 许可证。
