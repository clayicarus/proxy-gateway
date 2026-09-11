# Changelog

## Unreleased

### Breaking correctness fixes

- Configurations containing `obfs` are now rejected at startup. Earlier versions
  parsed the field but did not connect it to the Gateway data plane, which could
  make an operator believe the listener was obfuscated when it was not. Remove
  the field before upgrading; no equivalent Gateway setting is available.
- The legacy top-level `masquerade` field is no longer part of the runtime
  schema. It was likewise parsed but unused. Masquerade is now implemented per
  inbound: `migrate-inbounds` converts the legacy proxy mode into
  `inbounds[].masquerade` and reports that it starts taking effect after the
  upgrade.

### Operational changes

- Enabling `trojan.fallback` sets the listener's TLS ALPN to `http/1.1`, because
  the fixed backend receives plaintext HTTP/1.1 and never HTTP/2 frames. This is
  a configuration-only change with a client-visible effect: an existing Trojan
  client pinned to `h2` on that inbound stops completing the TLS handshake.
  Remove the client's ALPN pin or set it to `http/1.1`. Generated subscriptions
  already carry `alpn: [http/1.1]` for fallback-enabled inbounds.
- `migrate-inbounds` now fails instead of migrating when a legacy `trojan` block
  carries subscription metadata such as `sni` without `serverAddr`, because the
  generated subscription needs an explicit client-reachable address. Add
  `trojan.serverAddr` to the legacy file, or remove the metadata, before
  migrating.
- The default `trojan.fallback.maxConnections` is 128 rather than 32. Each
  website connection also holds one backend connection, so size it against the
  backend's capacity.

### Features

- Trojan inbounds accept optional `trojan.fallback` to serve an HTTP/1.1 website
  over the same TLS listener, following official initial-request classification.
  Both the complete request structure and credentials must pass before a proxy
  session is issued. Malformed or incomplete headers fall back even with correct
  credential prefixes, with lossless replay of up to 320 consumed header bytes
  and the unread stream. The configurable probe window covers the entire header.
  A fixed plaintext backend and independent connection/time limits bound website
  traffic, which bypasses user policy, accounting and request tracking. Local
  target rejection, dial failure, policy rejection and later UDP framing errors
  after valid request classification close the proxy connection without fallback.
  A connection that completes TLS but sends no request within the probe window is
  closed without taking a website slot or a backend connection, which also means
  browser preconnect sockets are dropped once the window expires. When website
  capacity is exhausted the Gateway answers with a bodyless 404 that carries no
  server identity, so exhaustion cannot be used to expose the listener by forcing
  a silent close. `idleTimeout` bounds a website connection by inactivity rather
  than by absolute lifetime: transfers in either direction extend it, so active
  visitors and keep-alive connections are no longer cut off mid-transfer. The
  backend address is rejected at startup if it points at the inbound's own listen
  address; a hostname is still accepted but is re-resolved per connection.
- Fallback-enabled Trojan subscriptions advertise `alpn: [http/1.1]`. A complete
  website configuration, static page and loopback Nginx origin example serve
  ordinary HTTPS and Hysteria2 HTTP/3, with subscriptions available at `/sub/`.
- Subscriptions can publish Trojan with the existing `sub.inbound` syntax, or
  several Hysteria2/Trojan listeners with `sub.endpoints`. Each published inbound
  has an explicit public address and independent client TLS settings. Trojan
  entries use raw per-node passwords and enable UDP ASSOCIATE.
- Mixed subscriptions distinguish protocol and inbound names, disambiguate node
  aliases, and include all entries in the selection group. Gateway `direct`
  entries retain TLS settings, and credential-bearing responses disable caching.
- Legacy Trojan subscription metadata is preserved during inbound migration when
  its listener, public address and subscription settings are configured.
- Hysteria2 inbounds accept `masquerade` with `type: proxy`. Every request that
  is not a Hysteria2 authentication request, which includes active probes, is
  forwarded to one fixed web backend, so the listener answers as an ordinary
  website instead of the previous 404 for everything. The Gateway does not add
  `X-Forwarded-*` headers and returns a bare 502 when the backend fails.
- Trojan inbounds support UDP ASSOCIATE in addition to TCP CONNECT. Datagrams
  travel inside the same TLS connection, each one is charged before it leaves the
  Gateway, and `trojan.udpIdleTimeout` reclaims idle associations.

### Portability fixes

- Embed timezone data so standalone Gateway and configuration tools can use
  named zones on Windows and systems without an installed timezone database.
- Generate temporary TLS certificates for Trojan and interoperability tests.
  Upstream fixture builds inherit the Go cache configuration and use executable
  suffixes on Windows, without requiring certificate files outside Git.

### Inbound refactor preparation

- Added offline strict validation for the future named `inbounds` schema.
- Added `scripts/validate-inbounds` as the offline validator entry point.
- Added `scripts/migrate-inbounds`, which converts legacy YAML without opening
  SQLite, loading certificates, binding listeners, or overwriting its output.
