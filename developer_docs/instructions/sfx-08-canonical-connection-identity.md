# sfx-08 — Canonical connection identity and sole producer authority

**Architect approval:** conversation 2026-11-23. Implement the first bounded
`CONN_ID` round in Wintap and Wintap-PyUtil without deployment or historical-data
mutation.

## Required behavior

1. Wintap .NET is the sole `CONN_ID` generator.
2. Context plus protocol and both complete IP/port endpoint pairs contribute to
   identity. Reversing whole endpoint pairs preserves identity.
3. Opposite host sensors and same-host client/server perspectives for one tuple
   produce the same ID.
4. Ordinary host-local default-gateway metadata must not split identity. Continue
   recording it as metadata.
5. Preserve host scoping for loopback tuples so identical loopback tuples on
   different hosts do not collide.
6. Preserve the existing deterministic .NET preimage and nested hash convention;
   exact DBT JSON output is not a compatibility target.
7. DBT and legacy PyUtil raw views consume producer `connid` without recomputing it.

## Verification

Use SDK `~/.dotnet/wintap-sdk-10.0.402/dotnet`. Keep generated evidence under
`/data/lintap-compactor/sensor-fixes/conn-id-single-authority-20261123/`. Run
source-linked semantic vectors, compile the changed Wintap test source, and run
the available PyUtil SQL/raw-view contracts without installing dependencies.

## Limits

Do not deploy, mutate historical data, access network/S3, install dependencies,
or claim native Windows acceptance. Preserve completed Linux sensor fixes and do
not reopen deferred BPF/process-lifecycle work.
