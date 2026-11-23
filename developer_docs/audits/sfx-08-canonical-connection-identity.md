# sfx-08 — Canonical connection identity and sole producer authority

**Result:** implemented and accepted for the bounded source/contract round.
Wintap source-linked checks pass **32/32** endpoint-normalization cases. PyUtil
passes **222/222** contract plus connection-ID passthrough tests. A real local DBT
build passes all **11/11** selected nodes and materializes both synthetic producer
IDs unchanged. Native Windows execution remains deferred.

## Scope and implementation

Wintap retains its existing context, endpoint-pair ordering, nested preimage and
uppercase MD5 convention. `Transformer` no longer contributes ordinary default
gateways to `ConnId`, because opposite sensors can associate the same gateway with
opposite endpoint slots. Gateway values remain recorded in connection metadata.
Loopback continues to contribute the host-scoping value, preventing unrelated
hosts' identical loopback tuples from colliding.

Tests now cover opposite-host perspectives with non-empty gateway metadata,
ordinary gateway independence, loopback host scoping and reversal, context, both
IPs, both ports, protocol, and the pre-existing send/receive and same-IP cases.

Wintap-PyUtil silver DBT now preserves producer `connid`. The temporary SQL hash
macro and its exact-output contract were removed. Legacy `rawutil.get_raw_view`
also stopped recomputing `ConnId`; it preserves producer `ConnId` and adds a null
`AgentId` compatibility column only when that field is absent.

The real-DBT synthetic fixture now supplies producer `ConnId` values. Its focused
regression builds the bronze and silver network models, runs source/activity and
non-null tests, then queries the materialized DuckDB table to prove the TCP and UDP
producer IDs are preserved exactly.

Source bases: Wintap `45939db`; Wintap-PyUtil `564ec43`, branch
`feature/implement-sensor-fixes-and-cleanup-test-code`. Changes are local and not
pushed.

## Verification

Evidence is under:

```text
/data/lintap-compactor/sensor-fixes/conn-id-single-authority-20261123/
```

| Gate | Result |
|---|---|
| Actual Wintap source + changed test source, compiled directly with SDK 10.0.402 | Pass. |
| Network endpoint-normalization rows/facts | **32/32** pass. |
| Opposite sensors with gateway in opposite slots | Same `ConnId`. |
| Ordinary gateway change | Same `ConnId`; metadata retained. |
| Loopback | Same host/reversal stable; different hosts differ. |
| Context and every five-tuple field | Each field contributes; reversal stable. |
| PyUtil focused model/raw-view and consumer tests | **86/86** pass. |
| PyUtil classified SQL contracts plus raw-view tests | **222/222** pass. |
| Real local DBT producer-ID build | **11/11** selected operations/models/tests pass; both materialized producer IDs match exactly. |
| Broader compacted-input test file | **8/8** runnable tests pass; one explicitly opt-in destructive migration test skips. |
| Static single-authority scan and Python compilation | Pass. |

The normal Windows-targeted xUnit build did not execute on Linux. The first
no-restore attempt stopped at `NETSDK1100`; enabling Windows targeting then exposed
stale `net8.0` assets without a net10 Windows target. An existing-assets net8
compile attempt correctly refused net10 project references. No restore or
dependency installation was performed. Direct SDK compilation used the actual
changed production and test sources with minimal evidence-only stubs; this is a
bounded compile/semantic gate, not native Windows acceptance.

The broader PyUtil configuration module could not collect in the reused existing
environment because `dynaconf` is absent. No package was installed. All relevant
SQL, network consumer, and raw-view tests ran successfully in that environment.
The real DBT regression used an existing DBT 1.12.3/dbt-duckdb 1.9.6 environment
and a fresh fixture/database beneath the approved evidence root. No sync, install,
remote source or S3 access was used. The initial `dbt --version` probe was not
network-isolated and may have performed DBT's normal package-version metadata
check; the build itself used local fixtures with anonymous telemetry disabled.

## Limits

Current DBT materializations must be rebuilt together when this change is adopted;
old DBT-derived and producer-derived IDs must not be mixed silently. Historical
ACME4 rows are not repaired. No deployment, historical mutation, source-data/S3,
dependency installation, native Windows run or push occurred. The implementation
and this audit are included in the local milestone commit. The possible
version-metadata check above is the only network caveat.
