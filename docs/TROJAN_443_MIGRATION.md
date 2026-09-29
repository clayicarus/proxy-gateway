# 为 Wi-Fi 下的 Trojan 连接增加 TCP 443 入口

适用情况：同一账号的 Hysteria2 在 Wi-Fi 下可用，Trojan TCP 6800 失败，而 Trojan 在其他网络可用。新增 TCP 443 是可回退的入口对照方案，不代表已证明运营商封锁，也不能保证换端口必然解决。

项目已经支持多 Trojan 入口，无需修改协议代码或重新生成用户密码、订阅 token。本次只增加入口与订阅发布项，不调整 Hysteria2 参数或账号流量策略。

## 配置变更

完整可验证示例为 [gateway-trojan-443.yaml](../configs/gateway-trojan-443.yaml)。示例使用占位域名，不需要对外提供服务器 IP。

在现有运行 YAML 的 `inbounds` 列表中追加：

```yaml
  - name: trojan-443
    type: trojan
    listen: :443
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 256
      udpIdleTimeout: 60s
```

在现有 `sub.endpoints` 列表中追加相应公开入口，地址和 SNI 使用现有 Trojan 域名，仅把公网端口改为 443：

```yaml
    - inbound: trojan-443
      serverAddr: gateway.example.com:443
      sni: gateway.example.com
```

保留现有入口名称、6800 的发布项，以及全部 Hysteria2 配置。若原配置使用单入口 `sub.inbound/serverAddr/sni/insecure`，先将原发布项移入 `sub.endpoints` 再追加，不能混用两种写法。已有多入口配置直接追加即可。

不要用完整示例覆盖运行配置：保留原 `dbPath`、证书、时区、管理员监听、订阅 URL 及其他参数。新增入口复用已有证书、账号与节点授权；不执行数据库迁移。

## TCP 443 的占用与网站共存

Hysteria2 UDP 443 与 Trojan TCP 443 可以同时监听。已有 HTTPS 网站、Nginx/Caddy 的 TCP 443 则不能与 Gateway 绑定同一个地址。

服务器端只需在本机检查，不用向外提供地址：

```sh
ss -lntp 'sport = :443'
```

- TCP 443 空闲：Gateway 可直接新增监听。
- TCP 443 已被网站占用：先保留网站原有虚拟主机和路由，把其 HTTP 源站准备到 `127.0.0.1:8080`，为新 Trojan 入口启用下面的 `fallback`，再在同一个维护窗口中把公网 TLS 交给 Gateway。不要直接关闭网站或覆盖其配置。
- 无法迁移现有 TCP 443 服务：暂不应用本方案；需要由部署环境提供另一可用地址/四层入口，不能仅改客户端端口。

```yaml
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 256
      udpIdleTimeout: 60s
      fallback:
        addr: 127.0.0.1:8080
        probeTimeout: 1s
        dialTimeout: 3s
        idleTimeout: 30s
        maxConnections: 32
```

网站共存复用项目已有功能，示例见 [masquerade-nginx.conf](../configs/masquerade-nginx.conf) 和 [gateway-website.yaml](../configs/gateway-website.yaml)。Fallback 接受明文 HTTP/1.1 源站，不能指向 HTTPS URL。若网站承载原订阅 URL，要保留 `/sub/` 到 `127.0.0.1:9091` 的转发；Gateway 证书必须覆盖它接管的所有域名。已有 HTTP/2、其他 TLS 协议或独立证书需求不能直接套用这个 HTTP/1.1 示例。

启用 fallback 后，订阅会自动为新入口输出 `alpn: [http/1.1]`。普通 Nginx `location` HTTP 反向代理不能承载 Trojan；也不能假定 HTTP CDN 会转发任意 Trojan TCP 流量。

## 应用与回退

1. 备份当前运行 YAML；如果迁移网站，同时备份对应网站配置。先准备候选配置，保留旧 6800 入口。
2. 使用项目已有校验器验证候选配置：

   ```sh
   validate-inbounds --input /path/to/gateway-candidate.yaml
   ```

   此命令只校验 schema，不证明端口空闲、证书可读或公网可达。如修改 Nginx，另运行 `nginx -t`。
3. 确认云安全组、主机防火墙和容器/NAT（若使用）允许并映射 TCP 443；这与现有 UDP 443 是不同规则。Gateway 运行账户需具备绑定特权端口的权限，项目 systemd 示例使用 `CAP_NET_BIND_SERVICE`。
4. 在短维护窗口中应用候选配置，并按实际服务名称重启 Gateway。入站配置不是热加载，重启会短暂中断现有会话；本地客户端配置修改无法代替此步骤。
5. 检查新 TCP 443、旧 TCP 6800 均监听，原订阅 URL 和网站（如有）仍可访问。若新服务启动失败或影响原业务，恢复备份配置与原网站监听后重启；不要重置数据库或订阅 token。

## Wi-Fi 验收：只做低流量实际请求

1. 服务端应用完成后，Clash Verge 更新原来的 `pien.yaml` 订阅。
2. 多个 Trojan 入口会使节点名称带入口后缀，例如 `香港CF-trojan-trojan-443` 与 `香港CF-trojan-trojan-public`。选择名称带 `trojan-443` 的节点，并确认详情端口为 443；旧选择可能因名称变化需要重新指定。
3. 回到原 Wi-Fi，保持原来的 TUN + 系统代理 + 规则设置，用浏览器只打开一次 `https://linux.do/latest`。不要通过三毛机场或链式代理进行这项验收。
4. 443 可访问而 6800 失败，才能确认新增入口解决了这条 Wi-Fi 路径上的问题。若两者都失败，保留旧入口并继续排查，不能把本方案标为成功。
5. 网页返回 Cloudflare 验证（例如 HTTP 403 且 `Cf-Mitigated: challenge`）说明请求已到达网站，不等于 TCP/TLS 超时；用正常浏览器完成人机验证。延迟测速数值不能替代实际访问验收。

本仓库提供配置与验证，不会自动登录服务器、修改防火墙、重启服务或更换客户端正在使用的订阅。
