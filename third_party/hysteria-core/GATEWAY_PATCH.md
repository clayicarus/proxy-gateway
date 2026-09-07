# Gateway patch

Base: `github.com/apernet/hysteria/core/v2 v2.8.1`

This directory is a source-pinned fork used by Proxy Gateway. The upstream
wire protocol, frame encoding, authentication headers, and default legacy APIs
remain unchanged. Gateway-specific additions are limited to:

- context-aware client connect and TCP request operations;
- stable server transport, session, and request identities;
- session-aware outbound, traffic, and lifecycle callbacks;
- explicit close plus context-bounded wait for server/client workers;
- UDP callbacks at the existing per-fragment/per-send-attempt accounting points.

`LICENSE.md` is the original MIT license. Changes must remain reviewable against
the tagged v2.8.1 source and must pass both legacy and Gateway capability tests.
