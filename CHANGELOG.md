# Changelog

## Unreleased

### Breaking correctness fixes

- Configurations containing `obfs` or `masquerade` are now rejected at startup.
  Earlier versions parsed these fields but did not connect them to the Gateway
  data plane, which could make an operator believe the listener was obfuscated
  or serving masquerade content when it was not. Remove these fields before
  upgrading; no equivalent Gateway setting is currently available.

### Inbound refactor preparation

- Added offline strict validation for the future named `inbounds` schema.
- Added `scripts/validate-inbounds` as the offline validator entry point.
- Added `scripts/migrate-inbounds`, which converts legacy YAML without opening
  SQLite, loading certificates, binding listeners, or overwriting its output.
