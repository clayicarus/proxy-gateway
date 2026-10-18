**English** | [中文](README.zh.md)

# Proxy Gateway

A multi-user Hysteria2 and Trojan proxy gateway for managing users, outbound nodes, subscriptions and traffic quotas on one server. Clients select authorized nodes; Gateway handles authentication, routing and traffic policies.

## Features

### Inbound and outbound forwarding

- **Inbounds**: Hysteria2 and [Trojan](docs/TROJAN_INBOUND_DESIGN.md), with TCP and UDP proxying.
- **Outbounds**: remote Hysteria2 nodes or Gateway's `direct` route to the destination.
- **Traffic policies**: user and node authorization, expiry enforcement, calendar-month quotas and per-user aggregate download limits.
- **Node recovery**: background reconnection for unavailable nodes; clients handle node selection and failover.
- **Website serving**: optional Hysteria2 HTTP/3 masquerading and Trojan HTTPS fallback.

Accounting measures payload upload and download through Gateway, including its `direct` route. Client-local `DIRECT`, QUIC/IP headers and retransmissions are excluded. See the [architecture](docs/ARCHITECTURE.md) for the forwarding path and the [core integration guide](docs/INTEGRATION.md) for Hysteria2 integration.

### Management panel

- **Users**: create, disable or enable accounts, reset passwords and subscription URLs, and configure expiry dates, monthly quotas and download limits.
- **Nodes and grants**: manage node settings, enabled status and aliases, assign user access, and select all nodes when creating a user.
- **Subscriptions**: generate Clash.Meta / Mihomo subscriptions with mixed protocols, monthly usage, quota and expiry information.
- **Monitoring**: inspect active connections, live speeds, traffic statistics, cost estimates and node status.
- **Operations**: inspect configuration application status and process exit records, and schedule immediate or timed systemd restarts.

User and node settings are stored in SQLite. See the [management panel guide](docs/ADMIN_DESIGN.md) for configuration application rules and subscription behavior.

## Getting started

### 1. Get the program

Download the Linux amd64 or arm64 archive from [Releases](https://github.com/clayicarus/proxy-gateway/releases), verify it against that release's `SHA256SUMS`, and extract it. Archives contain the static `proxy-gateway` binary and example configurations. The host needs CA certificates and timezone data.

Alternatively, build from source with Go 1.24+ and a C compiler:

```bash
git clone https://github.com/clayicarus/proxy-gateway.git
cd proxy-gateway
CGO_ENABLED=1 go build -ldflags "-s -w" -o proxy-gateway ./cmd/gateway
```

### 2. Configure and start

Prepare a domain, TLS certificate and private key, then copy the [base configuration](configs/gateway.yaml):

```bash
cp configs/gateway.yaml gateway.yaml
```

Edit `gateway.yaml`:

- `tls.cert`, `tls.key`: certificate and private key paths, readable by the service user.
- `inbounds`: client-facing listeners; the default example uses Hysteria2 on UDP `8443`.
- `sub.serverAddr`, `sub.sni`: the public domain and port clients connect to, and the certificate's domain.
- `sub.publicURL`: the public subscription URL prefix, such as `https://sub.example.com/sub/`.
- `dbPath`, `timezone`: a writable database path and the timezone for traffic accounting.

Start Gateway:

```bash
./proxy-gateway -c gateway.yaml
```

See the [mixed-protocol configuration](configs/gateway-mixed.yaml) to enable both inbounds, or the [website configuration](configs/gateway-website.yaml) for website masquerading and fallback.

### 3. Create users and connect

The management panel has no login authentication and listens only on loopback. Access it from your computer through SSH forwarding:

```bash
ssh -N -L 9090:127.0.0.1:9090 user@gateway.example.com
```

Open `http://127.0.0.1:9090`, add outbound nodes, create users and grant node access. You can grant `direct` first to connect directly through Gateway. Restart Gateway to apply node and grant changes.

Save the password and subscription URL when creating a user; they are shown only on creation or the corresponding reset. Publish the subscription service as described below, import the URL into a Hysteria2 / Trojan-capable Clash.Meta / Mihomo client, and select a node to connect.

## Deployment

Use systemd to manage Gateway on Linux, with watchdog support and graceful shutdown:

1. Install the program at `/usr/local/bin/proxy-gateway` and the configuration at `/etc/proxy-gateway/gateway.yaml`.
2. Use a dedicated service user with read access to the certificate files and write access to `/var/lib/proxy-gateway/`. Set `dbPath` to an absolute path inside that directory.
3. Create the service user and systemd unit following the [systemd deployment steps](docs/DEPLOYMENT.md#4-systemd-部署), then start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now proxy-gateway.service
   sudo journalctl -u proxy-gateway.service -f
   ```

4. Open the configured inbound ports: UDP for Hysteria2 and TCP for Trojan. Both can use the same numeric port.
5. Follow the [subscription publishing steps](docs/DEPLOYMENT.md#7-发布订阅服务) to configure an HTTPS reverse proxy forwarding `/sub/` to `127.0.0.1:9091`, matching the public address in `sub.publicURL`. Access the management panel on `9090` only through SSH.

If Trojan occupies TCP `443`, use another address or port for a separate subscription HTTPS service, or use the fallback setup in the website example. See the [deployment guide](docs/DEPLOYMENT.md) for the systemd unit, panel restart permissions, subscription reverse proxy and legacy migration instructions.

## Acknowledgements

- [Hysteria](https://github.com/apernet/hysteria): the Hysteria2 protocol and core implementation.
- [quic-go](https://github.com/quic-go/quic-go) and its [apernet fork](https://github.com/apernet/quic-go): QUIC support.
- [Trojan](https://github.com/trojan-gfw/trojan): the Trojan protocol design and specification.
- [SQLite](https://www.sqlite.org/) and [go-sqlite3](https://github.com/mattn/go-sqlite3): data storage.
- [Lucide](https://lucide.dev/): management panel icons.

The project uses an in-repository patch based on Hysteria core v2.8.1 and preserves Hysteria2 wire protocol compatibility.

## License

This project is licensed under **MIT**. Third-party dependencies retain their respective licenses. Copyright and license notices for the bundled Hysteria core are available in [LICENSE.md](third_party/hysteria-core/LICENSE.md); Lucide icons use the ISC license.
