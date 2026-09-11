**English** | [中文](README.zh.md)

# Proxy Gateway

A multi-user gateway with Hysteria2 and Trojan inbounds. Clients explicitly select an authorized outbound node. Gateway handles authentication, routing, traffic accounting, quotas and download limits, with SQLite and a local web panel for management.

The project pins a minimal in-repository patch of Hysteria2 core v2.8.1. It adds request identity, cancellation and complete lifecycle hooks without changing the wire protocol.

## Features

- Multi-user authentication with `username:node:password`; the authentication ID is `username:node`
- SQLite management of users, nodes, node grants, expiry, monthly quotas, download limits and subscription tokens
- A loopback-only management panel with an overview, users, active connections, costs and failures
- Calendar-month accounting of `tx + rx` across all nodes, closing client sessions when their quota is exceeded
- Per-user aggregate download limits across all connections
- A separate public HTTP subscription service producing Hysteria2, Trojan or mixed Clash.Meta / Mihomo configurations
- Scheduled systemd restarts, watchdog notifications, graceful shutdown and process exit records
- Built-in Direct and remote Hysteria2 outbounds
- Trojan TCP CONNECT and UDP ASSOCIATE with credentials derived for each user and authorized node
- Optional website serving on both inbounds: Hysteria2 HTTP/3 masquerading and Trojan HTTPS fallback to a configured web backend

Gateway never automatically changes a proxy request's outbound node. A missing node, mismatched context or dial failure returns an error. Clients must explicitly select `direct`, and the user must be authorized for it.

At startup, Gateway preconnects enabled Hysteria2 nodes with up to eight concurrent attempts and waits up to ten seconds for the first round. One failed node does not block the others or Gateway startup. Requests to unavailable nodes fail immediately while background reconnection uses jittered exponential backoff, up to sixty seconds. Each attempt resolves DNS again; the application does not cache results, although the operating system or upstream resolver may. The panel shows node status, resolved addresses, last success, errors and the next retry time.

## Topology

```text
hy2 client ----QUIC/UDP--> Gateway --direct/hy2--> Node or target
trojan client --TLS/TCP--> Gateway --direct/hy2--> Node or target
                              |--HTTP/TCP--> Local management panel
                              `--HTTP/TCP--> Public subscription service
```

See the [architecture](docs/ARCHITECTURE.md) and [management panel design](docs/ADMIN_DESIGN.md).

## Build

Go 1.24+ and a C compiler are required. The SQLite driver uses CGO.

```bash
CGO_ENABLED=1 go build -ldflags "-s -w" -o proxy-gateway ./cmd/gateway
CGO_ENABLED=1 go test ./...
```

Cross-compilation requires a suitable C cross-compiler. You can also build directly on the target Linux machine.

## Quick start

### 1. Configure startup settings

```yaml
inbounds:
  - name: hy2-public
    type: hysteria2
    listen: :8443
    masquerade:
      type: proxy
      proxy:
        url: http://127.0.0.1:8080
        rewriteHost: true
  - name: trojan-public
    type: trojan
    listen: :8443
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 256
      udpIdleTimeout: 60s

tls:
  cert: /etc/proxy-gateway/cert.pem
  key: /etc/proxy-gateway/key.pem

admin:
  listen: "127.0.0.1:9090"

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

dbPath: /var/lib/proxy-gateway/traffic.db
trafficFlushInterval: 10s
timezone: "Asia/Shanghai"

systemd:
  unit: "proxy-gateway.service"
  watchdog: true
```

Both `tls.cert` and `tls.key` are required. Named `inbounds` can use Hysteria2 over UDP or Trojan over TCP; the two protocols may share a numeric port. Hysteria2 `masquerade` is optional; see “Inbound masquerading” below. `sub.endpoints` lists the Hysteria2 or Trojan inbounds to publish, each with its public address and TLS settings. `admin.listen` and `sub.listen` are separate HTTP/TCP listeners. `sub.publicURL` is the subscription URL prefix; each `serverAddr` is the address clients use to reach that inbound. Public addresses must be explicit and are never inferred from listener addresses.

Users and nodes do not belong in the runtime YAML. Create them in the management panel after startup.

### 2. Start Gateway

```bash
install -d -o proxygateway -g proxygateway -m 0750 /var/lib/proxy-gateway
./proxy-gateway -c /etc/proxy-gateway/gateway.yaml
```

The SQLite directory is created automatically, but the service user must be able to write to its parent. The systemd `WorkingDirectory` also affects a relative `dbPath`; use an absolute path in production.

### 3. Open the management panel

The panel has no login authentication and configuration requires a loopback address. Access it through SSH forwarding:

```bash
ssh -L 9090:127.0.0.1:9090 root@gateway.example.com
```

Open `http://127.0.0.1:9090` in a browser. Writes require POST and a CSRF token; sensitive actions also require frontend confirmation. Origin/Referer are not used as the security boundary for SSH-forwarded access.

Node definitions and grants take effect after restart. Passwords, disabled status, expiry, quotas and speed limits refresh within about two seconds. Disabled, expired or over-quota sessions close the corresponding QUIC connection or Trojan session before the next payload is forwarded. Completely idle sessions are not actively scanned; protocol timeouts, client disconnection or Gateway restart can still close them.

### 4. Connect a client

```yaml
server: gateway.example.com:8443
auth: alice:node1:generated_password
tls:
  sni: gateway.example.com
```

Use the subscription URL generated by the panel. Its proxy entries correspond to authorized nodes; the client chooses nodes and handles failover.

### Clash.Meta / Mihomo subscriptions

A subscription creates one entry for each authorized node and each published inbound. The example above publishes both Hysteria2 and Trojan; a complete file is available at [configs/gateway-mixed.yaml](configs/gateway-mixed.yaml). For a single inbound, the original syntax remains supported and can select Trojan:

```yaml
sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  inbound: trojan-public
  serverAddr: "gateway.example.com:8443"
  sni: "gateway.example.com"
```

Do not combine `sub.endpoints` with the top-level `sub.inbound/serverAddr/sni/insecure` fields. List each inbound once. Its public port may differ from its listening port; use `[2001:db8::1]:443` for IPv6. Each endpoint has independent `sni` and `insecure` settings, with certificate verification enabled by default.

Trojan entries contain `type: trojan`, the raw `username:node:password` and `udp: true`. Mixed subscriptions add protocol suffixes to names. Multiple inbounds of one protocol also include the inbound name. Duplicate aliases are disambiguated, while existing single-Hysteria2 subscriptions retain their node names. The selection group includes every generated entry and client-local `DIRECT`. The Gateway's `direct` route still requires an explicit user grant.

Older Clash cores without Hysteria2 support should use a Trojan-only subscription. Grants use the startup snapshot, while passwords and user status are read live. New users become available after restart, and rotating a subscription token invalidates its old URL immediately. Responses contain client credentials and use `Cache-Control: no-store`.

### Trojan clients

Trojan supports TCP CONNECT, UDP ASSOCIATE and optional HTTPS website fallback. BIND and mux are unsupported. UDP datagrams use the same TCP/TLS connection without a separate UDP listener. Associations share TCP's node authorization, quotas and speed limits. Each user and authorized node has a separate password:

```text
username:node:password
```

Set this raw value as the client's Trojan password; the protocol sends its SHA-224 inside TLS. Derived credentials are not separately persisted or logged; subscriptions include the raw value required by the client. Multiple Trojan entries let a user explicitly select among authorized nodes.

`trojan.udpIdleTimeout` reclaims a UDP association only when neither direction has carried a datagram; its default is sixty seconds.

### Inbound masquerading

Without `masquerade`, the Hysteria2 inbound returns 404 to unauthenticated HTTP/3 requests. With `type: proxy`, it forwards these requests to a fixed web backend and serves that site's responses:

```yaml
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:8080
    rewriteHost: true
```

- `url` is fixed by configuration and cannot be selected by a request. The inbound does not become an open proxy. Prefer a local origin; pointing back to the public domain adds a TLS round trip and may create a loop if the domain resolves to Gateway itself.
- `rewriteHost: true` sends the backend its own hostname, for virtual-host routing. The default preserves the probe's Host.
- Gateway does not send `X-Forwarded-*` or `Forwarded`. An unavailable backend produces an empty 502 response.
- This setting covers HTTP/3 on the Hysteria2 UDP port. Configure the separate Trojan fallback below for ordinary HTTPS over TCP.

On a Trojan inbound, `trojan.fallback` follows the [official Trojan classification rule](https://github.com/trojan-gfw/trojan/blob/3e7bb9aecdc694f9bcae8d646fae395f773d60f8/docs/protocol.md#L49): after TLS succeeds, only a complete, structurally valid request with valid credentials enters the proxy path. Other traffic goes to a fixed plaintext HTTP/1.1 backend:

```yaml
trojan:
  fallback:
    addr: 127.0.0.1:8080
    probeTimeout: 1s
    dialTimeout: 3s
    timeout: 30s
    maxConnections: 32
```

- `addr` is a fixed `host:port`, not a URL or TLS backend. Request bytes, including Host, are preserved; the client cannot select the destination. Point it at an HTTP origin, not Gateway's public TLS listener.
- After TLS, the complete initial header, including credentials and request, must arrive within `probeTimeout`, also bounded by the original handshake deadline. Unknown credentials, malformed requests and incomplete headers share this decision window. Website visitors therefore wait about this long before the first response on each TLS connection; the default is one second. A matching credential prefix does not extend the window. These timing and resource limits are local configuration choices.
- Gateway advertises only `http/1.1` through TLS ALPN. Generated Trojan subscriptions include `alpn: [http/1.1]` for this inbound. Manually configured clients should use the same setting; clients without ALPN also work. HTTP/2 translation is not provided.
- `maxConnections` bounds anonymous connections, including the decision wait. `timeout` bounds the total backend dial and relay lifetime after that wait; `dialTimeout` additionally limits dialing. Defaults are shown above. Website traffic has no proxy user, quota or download limiter and is excluded from per-user accounting. Shutdown closes both sides and waits for relay completion.
- All consumed initial-header bytes, at most 320, are replayed once and in order, followed by the unread stream. Invalid commands, addresses or CRLF, and truncated or timed-out headers also fall back when the credential prefix is correct.
- Once the complete structure and credentials pass validation, local target rejection, dial failure, policy rejection or later UDP framing errors close the proxy connection. An unavailable website backend closes without a Gateway response. Omitting `fallback` retains close-on-failure behavior.

The complete [website configuration](configs/gateway-website.yaml) serves the bundled [Field Notes page](configs/masquerade-site/index.html) on TCP and UDP port 443. For a local page demo, run this from the repository root:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory configs/masquerade-site
```

For deployment, copy the page to `/var/www/field-notes/` and include the [Nginx origin configuration](configs/masquerade-nginx.conf) from Nginx's `http` context. It binds loopback port 8080, advertises HTTP/3 on public port 443, and forwards `/sub/` to the separate subscription service on 9091. Set the domain and certificate paths in `gateway-website.yaml`; the page can be replaced with your own static site. The Python demo serves files only and does not publish subscriptions. See the [deployment guide](docs/DEPLOYMENT.md) for port and TLS setup.

## Migrate legacy YAML

Keep the original `users`, `nodes` and secret, then run:

```bash
migrate -c /etc/proxy-gateway/legacy-gateway.yaml
```

Legacy subscription tokens use `sub.secret`, falling back to `api.secret`. Migration stores their hashes in SQLite so existing URLs remain usable. After management-data migration, convert runtime settings with the management fields and secrets removed:

```bash
scripts/migrate-inbounds --input /etc/proxy-gateway/legacy-runtime.yaml --output /etc/proxy-gateway/gateway.yaml
scripts/validate-inbounds --input /etc/proxy-gateway/gateway.yaml
```

Runtime configuration rejects the old top-level `listen/quic/api`, `users`, `nodes`, `obfs` and `masquerade` fields. If the old configuration contains an enabled Trojan listener, subscription settings and `trojan.serverAddr`, migration preserves its public address, SNI and verification setting in a mixed subscription, and reports that Trojan is now published.

To atomically replace database users and grants from legacy YAML:

```bash
migrate --replace-users -c /etc/proxy-gateway/legacy-gateway.yaml
```

This preserves nodes, traffic, restart and process history, but removes managed users absent from the YAML. See the [deployment guide](docs/DEPLOYMENT.md).

## Traffic accounting

- `tx`: payload sent by the client through Gateway to a node or target.
- `rx`: payload sent by a node or target through Gateway to the client.
- User monthly quota: `tx + rx` across all of that user's nodes.
- Estimated Gateway egress: `tx + rx`.
- Estimated node egress: `tx + rx` for non-`direct` nodes.

These are payload estimates, excluding QUIC/IP headers and retransmissions. Gateway and node formulas represent two server perspectives and must not be added together as one machine's traffic.

## SQLite

The main tables are:

| Table | Purpose |
|---|---|
| `managed_users` | Users, lifecycle, quotas, speed limits and token hashes |
| `managed_nodes` | Node configuration and enabled status |
| `user_nodes` | User node grants |
| `traffic_logs` | Traffic increments at each flush |
| `traffic_summary` | Cumulative user and node traffic |
| `config_state` | Saved and running revisions |
| `management_migrations` | Data migration markers |
| `restart_jobs` | Scheduled restart jobs |
| `process_runs` | Process execution and exit history |

Timestamps use UTC Unix seconds. Convert them explicitly when querying:

```sql
-- Cumulative traffic for all users
SELECT user_id, node_id, tx_total, rx_total FROM traffic_summary;

-- User traffic during the last 24 hours
SELECT SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
WHERE user_id = 'alice' AND created_at >= unixepoch('now', '-1 day');

-- Aggregate by UTC date
SELECT date(created_at, 'unixepoch') AS day,
       SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
FROM traffic_logs
GROUP BY day ORDER BY day;

-- Display readable UTC timestamps
SELECT datetime(created_at, 'unixepoch') AS created_utc, user_id, node_id
FROM traffic_logs ORDER BY created_at DESC LIMIT 20;
```

Calendar-month quotas and panel range queries use the YAML `timezone` to calculate UTC boundaries. SQLite local-date functions are not a substitute.

## Configuration fields

| Field | Description |
|---|---|
| `inbounds[].listen` | Named Hysteria2 UDP or Trojan TCP listener |
| `inbounds[].masquerade` | Optional Hysteria2 HTTP/3 reverse proxy to a fixed website |
| `inbounds[].trojan.fallback` | Optional Trojan HTTPS fallback with a fixed HTTP/1.1 backend and independent limits |
| `tls.cert` / `tls.key` | Required TLS certificate and private key files |
| `admin.listen` | Management panel listener; must use loopback |
| `sub.listen` | Separate subscription HTTP listener |
| `sub.publicURL` | Public subscription URL prefix shown in the panel |
| `sub.inbound` | Hysteria2 or Trojan name for a single-inbound subscription |
| `sub.serverAddr` | Public Gateway address for a single-inbound subscription |
| `sub.endpoints[]` | Multiple published inbounds, each with `inbound/serverAddr/sni/insecure` |
| `sub.sni` / `sub.insecure` | Generated client TLS settings |
| `dbPath` | SQLite path; defaults to `proxy-gateway.db` |
| `trafficFlushInterval` | Traffic flush interval; defaults to `10s` |
| `timezone` | Calendar-month and panel query timezone; defaults to `UTC` |
| `systemd.unit` | Fixed systemd unit the panel can control |
| `systemd.watchdog` | Whether to send systemd watchdog notifications |

## Project layout

```text
cmd/gateway/       Startup, migration, exit records and lifecycle
internal/api/      Management web panel and database subscriptions
internal/auth/     User authentication and live refresh
internal/config/   Runtime YAML and legacy configuration parsing
internal/connection/ Active connection tracking
internal/inbound/  Protocol adapters and protocol library boundary
internal/outbound/ Direct, Hy2 node clients, retries and connection resources
internal/router/   Protocol-independent policy routing
internal/storage/  SQLite schema and queries
internal/subtoken/ Subscription tokens
internal/systemd/  D-Bus restarts and watchdog notifications
internal/traffic/  Traffic, quotas and download limits
test/              Integration and end-to-end tests
docs/              Design, integration and deployment documentation
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Management panel design](docs/ADMIN_DESIGN.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Hysteria2 integration](docs/INTEGRATION.md)
- [Development roadmap](docs/ROADMAP.md)

## License

MIT
