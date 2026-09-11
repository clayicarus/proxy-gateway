# Proxy Gateway 部署指南

## 前置条件

- Gateway 主机和可用的 UDP 公网端口
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

## 2. TLS 证书

Gateway 只加载 YAML 中 `tls.cert` 和 `tls.key` 指定的证书文件。部署时把证书和私钥放到 service 用户可读的位置。使用自签证书测试时，生成的订阅必须配置 `sub.insecure: true`，或让客户端信任该证书：

```bash
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
  -subj "/CN=gateway.example.com"
```

域名证书通常不包含 IP SAN。客户端用 IP 连接但仍校验证书时会收到 `cannot validate certificate ... because it doesn't contain any IP SANs`；应使用证书覆盖的域名作为 `sub.serverAddr`，并设置一致的 `sub.sni`。

## 3. 启动配置

创建 `/etc/proxy-gateway/gateway.yaml`：

```yaml
inbounds:
  - name: hy2-public
    type: hysteria2
    listen: :8443
    # Optional QUIC parameters.
    # quic:
    #   maxIdleTimeout: 30s
    #   maxIncomingStreams: 1024

tls:
  cert: /etc/proxy-gateway/cert.pem
  key: /etc/proxy-gateway/key.pem

# obfs is unsupported and rejected at startup.
# Hysteria2 masquerade is optional; see the website section below.

admin:
  listen: "127.0.0.1:9090"

sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  inbound: hy2-public
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
| `inbounds[].listen: :8443` | UDP/QUIC | 具名 Hysteria2 客户端流量入口 |
| `admin.listen: 127.0.0.1:9090` | HTTP/TCP | 本地管理后台 |
| `sub.listen: 127.0.0.1:9091` | HTTP/TCP | 订阅内容服务 |

`sub.publicURL` 是后台展示给用户的订阅链接前缀；`sub.serverAddr` 是生成配置里代理连接 Gateway 的公网地址。订阅服务自身是独立 HTTP listener；通过网站入口提供 `/sub/` 时，需要像下方完整示例那样由网站源站明确转发到订阅服务。

用户、节点和授权都在首次启动后通过后台创建。正常运行 YAML 不应包含顶层 `users`、`nodes` 或 `fallback`；网站回退必须配置在 `inbounds[].trojan.fallback` 下。

### 入站伪装

不配置 `masquerade` 时，Hysteria2 入站对所有非认证的 HTTP/3 请求返回 404。配置后，这些请求会被转发到一个固定的 web 后端：

```yaml
inbounds:
  - name: hy2-public
    type: hysteria2
    listen: ":8443"
    masquerade:
      type: proxy
      proxy:
        url: http://127.0.0.1:8080
        rewriteHost: true
```

要点：

- 目前只实现 `type: proxy`。`url` 是配置里的固定值，永远不受请求内容影响，因此入站不会变成开放代理。
- 建议指向本机源站（例如 `http://127.0.0.1:8080`），而不是绕回自己的公网域名：后者每次探测都要多一次公网 TLS 往返，而且当该域名解析到本机时可能形成环路。
- `rewriteHost: true` 时后端看到自己的 hostname，适合按虚拟主机分发的后端；默认保留探测者发来的 Host。
- Gateway 不会发送 `X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto` 或 `Forwarded`，因为一个普通网站不会暴露前面还有代理。后端不可用时返回空的 502，不含任何代理错误信息。
- 此配置只覆盖 Hysteria2 UDP 端口上的 HTTP/3；普通 HTTPS 使用下面的 Trojan TCP 网站回退。

### Trojan HTTPS 网站回退

在 Trojan 入口下启用可选的 `fallback`：

```yaml
inbounds:
  - name: trojan-public
    type: trojan
    listen: ":443"
    trojan:
      fallback:
        addr: 127.0.0.1:8080
        probeTimeout: 1s
        dialTimeout: 3s
        idleTimeout: 30s
        maxConnections: 32
```

Gateway 终止 TLS 后，将无有效 Trojan 凭据的字节流按原顺序送到 `addr`。后端必须提供明文 HTTP/1.1；不接受 URL，不向后端再发起 TLS，也不根据请求 Host、路径或 SNI 选择后端。Host 与其他请求字节保持原样，源站应为站点域名提供服务，或像示例那样使用默认虚拟主机。

`addr` 只来自配置，永不受请求内容影响。启动时会拒绝把它指回该入站自己的监听地址，避免每次探测都重新进入入站。允许写域名，但**每条回退连接都会重新解析一次**，等于把 DNS 放到了探测路径上；建议使用字面地址（如 `127.0.0.1:8080`）。

| 配置 | 默认值 | 有效范围与含义 |
|---|---|---|
| `probeTimeout` | `1s` | `50ms`–`10s`，TLS 成功后等待完整初始首部（凭据和请求）的窗口，同时受原始握手 deadline 限制 |
| `dialTimeout` | `3s` | `50ms`–`30s`，后端拨号上限 |
| `idleTimeout` | `30s` | `1s`–`10m`，双向都无传输时回收网站连接的空闲上限；任一方向的传输都会顺延，不是连接寿命上限 |
| `maxConnections` | `128` | `1`–`65535`，匿名网站连接总上限；每条同时占用一条源站连接，需与源站的并发能力匹配 |

按 [Trojan 官方规则](https://github.com/trojan-gfw/trojan/blob/3e7bb9aecdc694f9bcae8d646fae395f773d60f8/docs/protocol.md#L49)，完整初始请求结构与凭据必须同时有效才进入代理路径。格式错误、未知凭据、截断和读取超时都回退；即使凭据前缀正确，后续命令、地址或 CRLF 非法也会回退。已消费的最多 320 字节首部完整回放一次，再转发未读流。

判定完成后 Gateway 立即转发，不额外等待 `probeTimeout`：回退结果由源站作答，因此不存在需要抹平的 Gateway 侧时延差异。首包短于 58 字节（凭据加 CRLF）无法判定，会等到窗口到期才转发，这与普通 Web 服务器等待请求剩余部分的行为一致。

TLS 成功但在窗口内没有发出任何字节的连接被直接关闭，不占 `maxConnections` 槽位也不拨源站，避免少量静默连接挤掉真实访客。副作用是浏览器预连接会在窗口到期后被关闭，需要重新建连。

`maxConnections` 耗尽时 Gateway 返回一个不带 body、不含服务端标识的 `404`。这是网站路径上唯一由 Gateway 生成的响应，用来避免静默关闭暴露入站身份；它与源站自身的 404 并不相同，能同时取得两者的探测者仍可区分。后端无法连接时仍然直接关闭连接。

有效 Trojan 客户端也必须在这个窗口内发送完整首部，正确凭据前缀不会延长窗口。这些时间和资源上限是本地配置，官方协议不规定其数值。完整结构与凭据通过后，本地目标限制、拨号失败、策略拒绝及后续 UDP 分帧错误只关闭代理连接，不再回退。

启用后 TLS ALPN 只声明 `http/1.1`，生成的 Trojan 订阅自动带 `alpn: [http/1.1]`。手动客户端使用相同设置，或不发送 ALPN；只支持 `h2` 的客户端无法协商。网站访问不创建用户代理会话，不计入用户流量、额度或限速；独立资源上限和停机清理覆盖匿名连接。

完整示例见 [gateway-website.yaml](../configs/gateway-website.yaml)、[静态页面](../configs/masquerade-site/index.html) 和 [Nginx 源站配置](../configs/masquerade-nginx.conf)。将页面复制到 `/var/www/field-notes/index.html`，在 Nginx 的 `http` 上下文中包含源站配置，确认 Nginx 监听 `127.0.0.1:8080`。Gateway 同时占用 TCP 与 UDP 443，两个入口指向同一源站。修改示例中的域名、证书和数据文件路径后再启动 Gateway。

源站配置通过 `Alt-Svc` 声明 UDP 443 的 HTTP/3；若公网端口或 NAT 映射不同，需要同步修改该响应头及订阅中的 `serverAddr`。同一源站还把 `/sub/` 转到 `127.0.0.1:9091`，因此 `sub.publicURL` 可使用 `https://gateway.example.com/sub/`。管理后台继续使用 loopback 和 SSH 转发。

先用 `curl https://gateway.example.com/` 检查证书和网站；支持 HTTP/3 的 curl 可用 `curl --http3-only https://gateway.example.com/` 验证 UDP。随后从后台获取 token 订阅并测试 Trojan TCP/UDP。仓库内测试已覆盖使用受信任测试证书访问同一网站、经 HTTPS 获取订阅，以及按订阅建立代理连接。

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

管理后台和订阅服务在启动阶段同步绑定 TCP 端口。地址无效或端口占用会直接 fatal；启动后的 HTTP serve loop 异常退出也会让主进程以失败状态退出，避免 Gateway 存活但后台永久不可用。

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

同一 URL 可以同时发布 Hysteria2 与 Trojan。启用两个具名入站后，将单入口的 `sub.inbound/serverAddr/sni/insecure` 替换为以下列表；每项地址必须是客户端实际可达的地址，端口可与监听端口不同：

```yaml
sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  endpoints:
    - inbound: hy2-public
      serverAddr: "gateway.example.com:8443"
      sni: "gateway.example.com"
    - inbound: trojan-public
      serverAddr: "gateway.example.com:8443"
      sni: "gateway.example.com"
```

完整配置见 [gateway-mixed.yaml](../configs/gateway-mixed.yaml)。仅发布 Trojan 时可使用 `sub.inbound: trojan-public` 和原有单入口字段；两种写法不能混用。入口名称、地址和 TLS 参数在重启时应用。Trojan 条目使用原始 `username:node:password` 并启用 UDP；不要将 SHA-224 填入客户端的 password 字段。

Hysteria2 需要放行入口的 UDP 端口，Trojan 需要放行 TCP 端口，两者可共用数值端口。若 Trojan 占用 TCP 443，Nginx 不能再绑定同一地址的 TCP 443。可以为独立订阅 HTTPS 服务选择其他端口或 IP，也可采用上面的完整网站示例：由 Trojan 终止 TLS，Nginx 只监听 loopback HTTP，再把 `/sub/` 转发到订阅服务。

## 8. 旧配置迁移

迁移前备份 YAML 和数据库，并停止 Gateway，确保命令使用与 service 完全相同的 `dbPath`：

```bash
systemctl stop proxy-gateway.service
sudo -u proxygateway /usr/local/bin/migrate \
  -c /etc/proxy-gateway/legacy-gateway.yaml
systemctl start proxy-gateway.service
```

旧 YAML 必须包含用户、节点，以及 `sub.secret` 或回退使用的 `api.secret`。该命令只迁移管理数据：在一个事务中导入用户、节点、授权，并保存旧 HMAC token 的哈希。数据库已有管理用户或已迁移时会拒绝覆盖。

随后从不含管理数据和 secret 的旧运行参数生成唯一运行时 schema，输出路径必须不存在：

```bash
sudo -u proxygateway /usr/local/bin/migrate-inbounds \
  --input /etc/proxy-gateway/legacy-runtime.yaml \
  --output /etc/proxy-gateway/gateway.yaml
sudo -u proxygateway /usr/local/bin/validate-inbounds \
  --input /etc/proxy-gateway/gateway.yaml
```

新运行时只接受具名 `inbounds`；旧顶层 `listen/quic/api` 和管理字段会明确拒绝。`obfs` 无数据面实现，迁移与运行时都拒绝。旧顶层 `masquerade` 的 `type: proxy` 会被迁移到 `inbounds[].masquerade`，迁移输出会提示它升级后开始生效；其他 masquerade 模式仍未实现，迁移会报错。

如果数据库用户表已错误，需要以旧 YAML 完整重建用户和授权：

```bash
systemctl stop proxy-gateway.service
cp /var/lib/proxy-gateway/traffic.db /var/lib/proxy-gateway/traffic.db.backup
sudo -u proxygateway /usr/local/bin/migrate --replace-users \
  -c /etc/proxy-gateway/legacy-gateway.yaml
systemctl start proxy-gateway.service
```

`--replace-users` 会删除 YAML 中不存在的管理用户，并替换密码、额度、限速和授权；节点、流量、进程和重启历史保留。YAML 引用的非 `direct` 节点必须已存在于数据库，任何失败都会回滚整个事务。

## 9. 验证

项目没有旧版 `/health`、`/traffic` 管理 JSON API。使用以下检查：

```bash
# 后台 HTTP 可达
curl -I http://127.0.0.1:9090/

# 监听端口；8443 应为 UDP，9090/9091 应为 TCP
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

# Nginx 公网 HTTPS（发布订阅时）
ufw allow 443/tcp

# 不开放 9090；9091 绑定 loopback 时也无需开放
```

远端 Hysteria2 Node 对 Gateway 开放相应 UDP 端口。

## 11. Docker 限制

基本容器运行示例：

```bash
docker run -d \
  --name proxy-gateway \
  --restart unless-stopped \
  -v /etc/proxy-gateway:/etc/proxy-gateway:ro \
  -v /var/lib/proxy-gateway:/var/lib/proxy-gateway \
  -p 8443:8443/udp \
  -p 127.0.0.1:9090:9090/tcp \
  -p 127.0.0.1:9091:9091/tcp \
  proxy-gateway -c /etc/proxy-gateway/gateway.yaml
```

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

SQLite 默认每 10 秒写入一次，进程被强制终止时最多损失一个 flush 周期。正常 flush 使用事务；写入失败会把整批增量恢复到内存，并在下一个周期重试。实时速度来自后台 `/live` 的内存快照；范围查询会先触发一次 flush。所有数值都是有效负载，不含协议包头和重传。

### 停用或到期后旧连接仍短暂存在

生命周期状态最多约 2 秒刷新。刷新后新连接会被拒绝；已有会话的下一笔 TCP/UDP 有效负载会在转发和计量前被拒绝，随后关闭整条 QUIC 连接。完全空闲的连接不会被后台主动扫描并立刻关闭，仍可能显示在活跃连接中，直到客户端断开、再次发送流量、QUIC idle timeout 或 Gateway 重启。这是当前 Hysteria2 server API 未提供按用户主动关闭空闲连接所带来的限制，不代表过期用户仍可继续传输数据。
