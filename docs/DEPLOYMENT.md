# Proxy Gateway 部署指南

## 前置条件

- Gateway 主机和可用的 UDP 公网端口；启用 Trojan 时还需 TCP 公网端口
- 可选的远端 Hysteria2 Node
- TLS 证书与私钥文件
- 构建环境使用 Go 1.24+ 和 C 编译器；运行环境不需要 Go
- 推荐 systemd 和 SQLite CLI

管理后台没有登录鉴权，只允许绑定 loopback，默认通过 SSH 端口转发访问。订阅服务与后台是两个独立 HTTP listener，可以单独反向代理到公网。

## 1. 构建

SQLite 驱动依赖 CGO：

```bash
CGO_ENABLED=1 go build -ldflags "-s -w" -o proxy-gateway ./cmd/gateway
CGO_ENABLED=1 go test ./...
```

跨平台编译还需要目标平台的 C 交叉工具链。最省事的方式是在目标 Linux 主机上构建，或使用项目 Dockerfile。

Windows 可使用已有 Conda/MinGW GCC，运行 `scripts/check.ps1`，通过 `-GoBin` 和 `-CCompiler` 指定安装路径。默认执行全量测试、race、vet、30 秒 fuzz、构建和格式检查；不依赖 Docker。Linux 的对应入口为 `make check`。

## 2. TLS 证书

Gateway 只加载 YAML 中 `tls.cert` 和 `tls.key` 指定的证书文件。部署时把证书和私钥放到 service 用户可读的位置。使用自签证书测试时，生成的订阅必须配置 `sub.insecure: true`，或让客户端信任该证书：

```bash
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
  -subj "/CN=gateway.example.com" \
  -addext "subjectAltName=DNS:gateway.example.com"
```

域名证书通常不包含 IP SAN。客户端用 IP 连接但仍校验证书时会收到 `cannot validate certificate ... because it doesn't contain any IP SANs`；应使用证书覆盖的域名作为 `sub.serverAddr`，并设置一致的 `sub.sni`。

## 3. 启动配置

创建 `/etc/proxy-gateway/gateway.yaml`：

```yaml
listen: :8443

# 可选 TCP/TLS 入站；删除该段可禁用 Trojan。
trojan:
  listen: :8443
  handshakeTimeout: 10s
  maxPendingConnections: 256

tls:
  cert: /etc/proxy-gateway/cert.pem
  key: /etc/proxy-gateway/key.pem

# 当前不支持 obfs、masquerade 或协议 fallback。

# 可选的 QUIC 参数
# quic:
#   maxIdleTimeout: 30s
#   maxIncomingStreams: 1024

admin:
  listen: "127.0.0.1:9090"

sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  serverAddr: "gateway.example.com:8443"
  sni: "gateway.example.com"
  insecure: false

dbPath: /var/lib/proxy-gateway/traffic.db
trafficFlushInterval: 10s
timezone: "Asia/Shanghai"

systemd:
  unit: "proxy-gateway.service"
  watchdog: true
```

端口含义：

| 配置 | 协议 | 用途 |
|---|---|---|
| `listen: :8443` | UDP/QUIC | Hysteria2 客户端流量入口 |
| `trojan.listen: :8443` | TCP/TLS | 可选 Trojan TCP CONNECT 入口 |
| `admin.listen: 127.0.0.1:9090` | HTTP/TCP | 本地管理后台 |
| `sub.listen: 127.0.0.1:9091` | HTTP/TCP | 订阅内容服务 |

`sub.publicURL` 是后台展示给用户的订阅链接前缀；`sub.serverAddr` 是生成配置里代理连接 Gateway 的公网地址。订阅服务不是 QUIC 网站，也不处理 Gateway UDP 端口上的 `/sub` 路径。

启用订阅时，`sub.serverAddr` 必须显式提供主机与端口，不能从通配监听地址推断。Trojan 第一期使用 [README 中的手工客户端配置](../README.md#4-客户端连接)，现有订阅仍只下发 Hysteria2。客户端 password 填入 `username:node:user.password`，不是 SHA-224 哈希；`udp` 设为 `false`。

Trojan 与 Hysteria2 可共用数字端口，因为一个使用 TCP、一个使用 UDP。Trojan 与 Nginx、后台、订阅 HTTP 则不能绑定相同 TCP 地址；例如启用 `trojan.listen: :443` 后，需给 Nginx HTTPS 选择不同 TCP 端口或独立 IP。

用户、节点和授权都在首次启动后通过后台创建。正常运行 YAML 不应包含 `users`、`nodes` 或 `fallback`。

## 4. systemd 部署

创建专用用户和目录：

```bash
useradd --system --home /var/lib/proxy-gateway --shell /usr/sbin/nologin proxygateway
install -d -o proxygateway -g proxygateway -m 0750 /var/lib/proxy-gateway
install -d -o root -g proxygateway -m 0750 /etc/proxy-gateway
install -o root -g root -m 0755 proxy-gateway /usr/local/bin/proxy-gateway
```

确保证书和 YAML 对 `proxygateway` 可读，私钥不要授予其他用户权限。创建 `/etc/systemd/system/proxy-gateway.service`：

```ini
[Unit]
Description=Proxy Gateway
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=proxygateway
Group=proxygateway
WorkingDirectory=/var/lib/proxy-gateway
ExecStart=/usr/local/bin/proxy-gateway -c /etc/proxy-gateway/gateway.yaml
ExecStopPost=/usr/local/bin/proxy-gateway record-exit -c /etc/proxy-gateway/gateway.yaml
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=control-group
WatchdogSec=30
NotifyAccess=main
LimitNOFILE=65535

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/proxy-gateway
ReadOnlyPaths=/etc/proxy-gateway

# 监听 443 等特权端口时需要
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`WorkingDirectory` 决定相对路径的解析位置。生产配置仍应使用绝对 `dbPath`，避免手动运行和 systemd 运行连接到不同数据库，这通常表现为 service 下用户全部“未知”。

加载并检查：

```bash
systemd-analyze verify /etc/systemd/system/proxy-gateway.service
systemctl daemon-reload
systemctl enable --now proxy-gateway.service
systemctl status proxy-gateway.service
systemctl show proxy-gateway.service \
  -p User -p Group -p WorkingDirectory -p MainPID -p ActiveState \
  -p SubState -p Result -p NRestarts -p WatchdogUSec
journalctl -u proxy-gateway.service -f
```

`status=217/USER` 表示 `User=` 或 `Group=` 不存在或 systemd 无法解析，应先用 `id proxygateway` 检查。不要仅为绕过错误而长期以 root 运行。

watchdog 能处理“进程存在但应用不再发送健康心跳”的假死，超时后 systemd 会终止并按 `Restart=on-failure` 重启。僵尸进程本身已经退出，systemd 会根据主进程状态处理；watchdog不是僵尸回收机制。当前心跳要求 Hysteria2 serve loop 正常且 SQLite 可 `Ping`，远端 Node 故障不会重启整个 Gateway。

管理后台、订阅服务和 Trojan 在启动阶段同步绑定 TCP 端口。地址无效或端口占用会直接失败；启动后的任一 serve loop 异常退出也会让主进程以失败状态退出。

## 5. 后台重启权限

后台保存节点或用户授权后会显示保存 revision 与运行 revision不同。到“故障分析”板块安排立即或定时重启；调度器把任务持久化后，通过 systemd D-Bus 请求 YAML 中固定的 unit。

非 root service 用户默认没有 `RestartUnit` 权限。可以配置严格限定 unit 的 polkit 规则，并在目标发行版验证 `action.lookup("unit")` 可用：

```javascript
// /etc/polkit-1/rules.d/50-proxy-gateway-restart.rules
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      subject.user == "proxygateway" &&
      action.lookup("unit") == "proxy-gateway.service") {
    return polkit.Result.YES;
  }
});
```

不要授予该用户控制任意 unit 的权限。若发行版不提供可安全限定 unit 的 polkit 上下文，应禁用后台重启能力，继续由管理员执行：

```bash
systemctl restart proxy-gateway.service
```

## 6. SSH 访问管理后台

从管理员电脑执行：

```bash
ssh -N -L 9090:127.0.0.1:9090 root@gateway.example.com
```

然后打开 `http://127.0.0.1:9090`。本机 9090 被占用时可改左侧端口，例如 `-L 19090:127.0.0.1:9090`，浏览器访问 `http://127.0.0.1:19090`。

后台没有登录鉴权，不能把 `admin.listen` 改为 `0.0.0.0`，程序也会拒绝该配置。不要通过 Nginx 发布管理后台。

## 7. 发布订阅服务

`configs/nginx-sub.conf` 把 `/sub/` 转发到 `127.0.0.1:9091`。示例 server：

```nginx
server {
    listen 443 ssl;
    server_name sub.example.com;

    ssl_certificate /etc/letsencrypt/live/sub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sub.example.com/privkey.pem;

    location /sub/ {
        proxy_pass http://127.0.0.1:9091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Cache-Control "no-store";
    }
}
```

订阅 URL 形如 `https://sub.example.com/sub/<token>`。token 本身就是 bearer credential，不要记录在公共日志或页面。重置 token 后旧 URL 立即失效。

## 8. 旧配置迁移

迁移前备份 YAML 和数据库，并停止 Gateway，确保命令使用与 service 完全相同的 `dbPath`：

```bash
systemctl stop proxy-gateway.service
sudo -u proxygateway /usr/local/bin/proxy-gateway migrate \
  -c /etc/proxy-gateway/legacy-gateway.yaml
systemctl start proxy-gateway.service
```

旧 YAML 必须包含用户、节点，以及 `sub.secret` 或回退使用的 `api.secret`。迁移在一个事务中导入用户、节点、授权，并保存旧 HMAC token 的哈希。数据库已有管理用户或已迁移时会拒绝覆盖。

运行和迁移都采用严格 YAML 解析。迁移前从旧 YAML 删除已废弃的 `fallback` 和未实现的 `obfs`、`masquerade`；未知字段及多个 YAML 文档会明确报错。

如果数据库用户表已错误，需要以旧 YAML 完整重建用户和授权：

```bash
systemctl stop proxy-gateway.service
cp /var/lib/proxy-gateway/traffic.db /var/lib/proxy-gateway/traffic.db.backup
sudo -u proxygateway /usr/local/bin/proxy-gateway migrate --replace-users \
  -c /etc/proxy-gateway/legacy-gateway.yaml
systemctl start proxy-gateway.service
```

`--replace-users` 会删除 YAML 中不存在的管理用户，并替换密码、额度、限速和授权；节点、流量、进程和重启历史保留。YAML 引用的非 `direct` 节点必须已存在于数据库且处于启用状态，任何失败都会回滚整个事务。

## 9. 验证

项目没有旧版 `/health`、`/traffic` 管理 JSON API。使用以下检查：

```bash
# 后台 HTTP 可达
curl -I http://127.0.0.1:9090/

# 监听端口；8443 为 UDP，启用 Trojan 时还应有 TCP；9090/9091 为 TCP
ss -lntup | grep proxy-gateway

# 数据库完整性与用户数量
sqlite3 /var/lib/proxy-gateway/traffic.db "PRAGMA integrity_check;"
sqlite3 /var/lib/proxy-gateway/traffic.db "SELECT COUNT(*) FROM managed_users;"

# systemd 状态和最近退出原因
systemctl status proxy-gateway.service
journalctl -u proxy-gateway.service -n 100 --no-pager
```

在后台创建测试用户并重启应用配置后，用后台显示的订阅 URL 验证：

```bash
curl -fS "https://sub.example.com/sub/<token>"
```

也可以用项目自带的 Python 脚本验证完整的 Hysteria2 链路。脚本需要已安装官方 `hysteria` v2 客户端；它通过临时本地 SOCKS5 代理连接目标 TCP 地址，因而会同时验证 QUIC、TLS、认证、节点路由和实际出站：

```bash
python3 scripts/hy2_connectivity.py \
  --server gateway.example.com:8443 \
  --auth 'alice:node1:generated_password' \
  --sni gateway.example.com \
  --target example.com:443
```

IPv6 字面量必须使用方括号，例如 `--server '[2001:db8::10]:8443'` 或 `--target '[2606:4700::1111]:443'`。自签证书的测试可额外使用 `--insecure`，生产环境不应使用该选项。

## 10. 防火墙

```bash
# Gateway Hysteria2 入口
ufw allow 8443/udp

# 可选 Trojan 入口
ufw allow 8443/tcp

# Nginx 公网 HTTPS（发布订阅时）
ufw allow 443/tcp

# 不开放 9090；9091 绑定 loopback 时也无需开放
```

远端 Hysteria2 Node 对 Gateway 开放相应 UDP 端口。

## 11. Docker 限制

Dockerfile 使用 Go 1.24、CGO 与 C 编译器构建，运行镜像包含 CA 和时区数据。本轮 Go 验收不要求 Docker 构建；容器部署还需在目标环境验证。

Linux 上可使用 host 网络保留后台和订阅的 loopback 绑定：

```bash
docker run -d \
  --name proxy-gateway \
  --restart unless-stopped \
  --network host \
  -v /etc/proxy-gateway:/etc/proxy-gateway:ro \
  -v /var/lib/proxy-gateway:/var/lib/proxy-gateway \
  proxy-gateway -c /etc/proxy-gateway/gateway.yaml
```

host 网络使用配置中的实际端口。普通 bridge 模式的 `-p` 端口映射不能访问容器内仅绑定 `127.0.0.1` 的后台；不能通过改为无鉴权公网绑定来解决。Docker Desktop 的网络行为需另行验证。

普通容器内无法访问宿主 systemd D-Bus，也不会获得 systemd watchdog 环境。因此后台重启、进程级 systemd 状态、watchdog 和 `ExecStopPost` 退出记录不可用；容器重启应交给 Docker 或外部编排器。不要为了这些功能把宿主 D-Bus 和高权限直接暴露进容器。

## 常见问题

### service 下鉴权全部失败

最常见原因是 service 读取了另一份数据库。检查 `ExecStart`、`WorkingDirectory`、YAML 的绝对 `dbPath` 和文件权限：

```bash
systemctl show proxy-gateway.service -p ExecStart -p WorkingDirectory -p User -p Group
sudo -u proxygateway sqlite3 /var/lib/proxy-gateway/traffic.db \
  "SELECT username FROM managed_users ORDER BY username;"
```

### Node 连接失败

Gateway 启动时最多并发预连接 8 个 Node，等待首轮结果最多 10 秒后继续启动。失败节点在后台以最长 60 秒的指数退避重连；请求不会等待重连，而是立即失败，也不会隐式回退到其他节点。每次连接尝试都会重新查询 DNS，应用自身不缓存结果，但 systemd-resolved、nscd、操作系统解析链或上游 DNS 仍可能命中缓存。后台节点状态会显示实际解析地址、最近错误和下次重试时间；同时核对 UDP 防火墙、auth、SNI 和证书。

### 修改后尚未生效

节点、新用户和用户节点授权需要重启。密码、停用、到期、额度和下载限速最多约 2 秒刷新。后台顶部的保存 revision 与运行 revision不同表示仍有待重启配置。

### 流量统计有延迟

SQLite 默认每 10 秒写入一次，正常持久化期间进程被强制终止时最多损失一个 flush 周期。正常 flush 使用事务；写入失败会保留整批增量及其所属自然月，在下个周期重试；持续写入故障期间未落盘数据会继续积累。读取月度用量失败时拒绝新流量，避免额度归零。实时速度来自后台 `/live` 的内存快照；范围查询会先触发一次 flush。所有数值都是有效负载，不含协议包头和重传。

### 停用或到期后旧连接仍短暂存在

生命周期状态最多约 2 秒刷新。刷新后新连接会被拒绝；已有会话的下一笔有效负载会在转发和计量前被拒绝，随后关闭 QUIC 连接或 Trojan TCP 会话。下载限速中的等待会因停用、到期或策略变更而唤醒；Trojan 连接断开也会取消该连接的等待。完全空闲的连接不会被后台主动扫描清理，仍可能显示在活跃连接中，直到客户端断开、再次发送流量、QUIC idle timeout（仅 Hysteria2）或 Gateway 重启。
