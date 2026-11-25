# sfx-09 — Host-scoped loopback connection context

**Architect approval:** conversation 2026-11-23. Refine the accepted sole-producer
`CONN_ID` contract so identical loopback tuples on different hosts cannot collide,
using explicit context rather than endpoint gateway slots.

## Required behavior

1. Determine connection context from the host-oriented local IPv4 endpoint.
2. If local IPv4 is in RFC 1122 loopback block `127.0.0.0/8`, use the observing
   hostname as connection context.
3. Otherwise use literal connection context `public`, replacing legacy `llnl` for
   connection identity only.
4. Do not contribute ordinary gateways or loopback host values through endpoint
   gateway slots in `ConnId`.
5. Preserve direction-independent whole-endpoint ordering, protocol, both IPs,
   both ports, gateway metadata fields, and all non-connection uses of the existing
   `llnl` Transformer context.
6. Wintap .NET remains the sole generator; DBT and legacy Python continue producer
   ID passthrough without rehashing.

## Verification

Use SDK `~/.dotnet/wintap-sdk-10.0.402/dotnet`. Add vectors for non-`.1` loopback
addresses, identical loopback tuples on distinct hosts, reversal on one host,
exact hostname/public contexts, and rejection of legacy `llnl` for non-loopback
connections. Keep evidence under
`/data/lintap-compactor/sensor-fixes/conn-id-loopback-context-20261123/`.

## Limits

This is an intentional connection-ID rekey. Do not deploy during this bounded
round, mutate historical data, access S3/source data, install dependencies, push,
or claim native Windows acceptance. DBT qualification may run now against fresh
local fixtures. Native Windows testing is deferred, not eliminated. Release uses
a clean cutover to newly collected data; no legacy migration or mixed-population
compatibility is required.
