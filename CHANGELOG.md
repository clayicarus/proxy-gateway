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

### Features

- Hysteria2 inbounds accept `masquerade` with `type: proxy`. Every request that
  is not a Hysteria2 authentication request, which includes active probes, is
  forwarded to one fixed web backend, so the listener answers as an ordinary
  website instead of the previous 404 for everything. The Gateway does not add
  `X-Forwarded-*` headers and returns a bare 502 when the backend fails.
- Trojan inbounds support UDP ASSOCIATE in addition to TCP CONNECT. Datagrams
  travel inside the same TLS connection, each one is charged before it leaves the
  Gateway, and `trojan.udpIdleTimeout` reclaims idle associations.

### Inbound refactor preparation

- Added offline strict validation for the future named `inbounds` schema.
- Added `scripts/validate-inbounds` as the offline validator entry point.
- Added `scripts/migrate-inbounds`, which converts legacy YAML without opening
  SQLite, loading certificates, binding listeners, or overwriting its output.
