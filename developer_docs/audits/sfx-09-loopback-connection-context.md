# sfx-09 — Host-scoped loopback connection context

**Result:** implemented and accepted for the bounded source/contract round.
Source-linked Wintap checks pass **33/33** endpoint-normalization cases. Focused
PyUtil passthrough contracts pass **78/78**, and all **11/11** selected nodes in
the real local DBT producer-ID materialization regression pass.

## Scope and implementation

`Transformer.CreateProcessConn` now derives the connection identity context from
the host-oriented local IPv4 endpoint after activity direction is classified:

- local IPv4 in RFC 1122 loopback block `127.0.0.0/8` uses the observing hostname;
- every non-loopback local IPv4 uses literal context `public`.

Both private-gateway namespace arguments passed to `GenKeyForFive_Tuple_Conn` are
empty. Ordinary gateways and loopback host values remain available in emitted
endpoint metadata, but gateway slots no longer affect `ConnId`. The existing
`Transformer.context = "llnl"` remains unchanged for non-connection identities,
including IP, file and registry keys.

This intentionally rekeys all newly generated connection IDs. Whole-endpoint
ordering, reversal stability, protocol and both IP/port pairs remain unchanged.
Wintap .NET remains the sole generator; DBT and legacy Python remain passthrough
consumers.

## Verification

| Gate | Result |
|---|---|
| Pre-change source-linked run | Expected red: exact hostname-context loopback assertion failed against the prior gateway-slot mechanism. |
| Changed Wintap production/test sources compiled directly with SDK 10.0.402 | Pass. |
| Source-linked endpoint-normalization harness | **33/33** pass, including a non-`.1` loopback address, distinct hosts, reversal, exact hostname context, exact `public` context and rejection of legacy `llnl` connection context. |
| PyUtil DBT/legacy passthrough contracts | **78/78** pass. |
| Real local DBT producer-ID materialization regression | **11/11** selected operations, models and tests pass; both synthetic producer IDs are preserved exactly. |
| Diff/static checks | Pass. |

Evidence is under
`/data/lintap-compactor/sensor-fixes/conn-id-loopback-context-20261123/`.

## Limits

Native Windows xUnit remains deferred. A normal no-restore net10 Windows build is
still blocked by Linux Windows-targeting requirements and stale net8 assets; no
restore was authorized. No dependency installation, S3/source-data access,
deployment, historical-data mutation or push occurred. DBT qualification is
complete for this round. Native Windows testing is deferred, not eliminated. The
release plan is a clean cutover to newly collected data, with no legacy migration
or mixed-population compatibility requirement.
