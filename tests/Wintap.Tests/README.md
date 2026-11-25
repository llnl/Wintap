# Wintap.Tests

Partial inventory for the first test-organization slice. This is still one xUnit
assembly targeting `net10.0-windows10.0.17763.0`; use **Windows and a stable .NET 10 SDK**.
`global.json` permits major-10 roll-forward from minimum 10.0.100 and excludes
prereleases. Record actual `dotnet --version` in verification evidence.
Linux-subject helpers in this assembly are not native Linux collector coverage.
Project references, linked sources, copied assets, dependencies, and release-CI
selection are unchanged.

## Reviewed slice

These five classes have class-level `TestKind=unit` and `Execution=synthetic`
traits. Existing `Category` traits and fully qualified test identities remain
unchanged; directories do not change the `Wintap.Tests` namespace.

| File | Subject | Facts | Theories | InlineData rows | Static case expectation |
|---|---|---:|---:|---:|---:|
| `Unit/Api/WintapMessageTests.cs` | Shared API constructor | 1 | 0 | 0 | 1 |
| `Unit/Shared/BoundedEventTimeCacheTests.cs` | Shared event-time cache | 11 | 2 | 4 | 15 |
| `Unit/Windows/File/WindowsFilePathNormalizerTests.cs` | Windows file-path helper | 5 | 3 | 42 | 47 |
| `Unit/Linux/File/FileOpsAggregatorTests.cs` | Linked Linux file aggregation helper | 10 | 0 | 0 | 10 |
| `Unit/Linux/File/FileOpsDenyPolicyTests.cs` | Linked Linux deny-policy parser | 4 | 0 | 0 | 4 |
| **Classified slice** | | **31** | **5** | **46** | **77** |
| `WindowsFilePathEmissionTests.cs` — unchanged neighbor | Windows producer/serializer contract | 1 | 2 | 6 | 7 |

Counts are lexical source expectations, **not discovered or passed results**.
No MemberData is used by this slice. The emission neighbor consumes
`WindowsFilePathNormalizerTests.Map`; include it whenever checking the moves, but
do not classify it as a unit solely because it shares that fixture.

Selected cases use synthetic inputs/injected callbacks and do not launch a
collector, generate host traffic, or read external datasets. Cache/normalizer
concurrency and culture restoration are retained. Synthetic does not imply a
time budget or portability: the assembly still references the Windows agent and
its runtime/native dependencies; no dependency or initialization bypass is added.

The remaining 58 C# files are not reorganized by this slice. Mixed source guards,
DuckDB/Esper/runtime-global fixtures, and native command probes must be reviewed
individually. Absence of these new traits is not a safe-execution classification.
Unfiltered `dotnet test` still includes native/integration cases; the traits do
not opt them out or change full-suite defaults.

## Focused Windows verification

Run from the Wintap repository root in the approved SDK environment. Record the
revision, dirty state (including shared sensor-worker edits), SDK, configuration,
and output provenance. If assets are missing, schedule an explicit locked restore;
do not install SDKs, update dependencies, or regenerate committed lockfiles as
part of this organization slice.

```powershell
dotnet --list-sdks
dotnet --version
dotnet restore tests/Wintap.Tests/Wintap.Tests.csproj --locked-mode
dotnet build tests/Wintap.Tests/Wintap.Tests.csproj -c Release --no-restore
dotnet test tests/Wintap.Tests/Wintap.Tests.csproj -c Release --no-build --no-restore --list-tests

$slice = 'FullyQualifiedName~Wintap.Tests.WintapMessageTests|FullyQualifiedName~Wintap.Tests.BoundedEventTimeCacheTests|FullyQualifiedName~Wintap.Tests.WindowsFilePathNormalizerTests|FullyQualifiedName~Wintap.Tests.FileOpsAggregatorTests|FullyQualifiedName~Wintap.Tests.FileOpsDenyPolicyTests|FullyQualifiedName~Wintap.Tests.WindowsFilePathEmissionTests'
dotnet test tests/Wintap.Tests/Wintap.Tests.csproj -c Release --no-build --no-restore --filter $slice

$classified = 'TestKind=unit&Execution=synthetic'
dotnet test tests/Wintap.Tests/Wintap.Tests.csproj -c Release --no-build --no-restore --list-tests --filter $classified
dotnet test tests/Wintap.Tests/Wintap.Tests.csproj -c Release --no-build --no-restore --filter $classified
```

Use a **120-second ceiling per command** initially, enforced by the runner.
Record timeout, discovery failure, skip, and zero-match results rather than
removing cases or silently running the full assembly. Discovery of the full
assembly can evaluate unrelated MemberData; listing is not a full-suite pass.
`--no-build` is valid only immediately after building the recorded sources and
configuration, never against stale binaries.

Expected selections are 84 focused cases (including the neighbor) and 77
classified cases in exactly the five reviewed classes. Confirm actual adapter
discovery/execution and existing Category selections on Windows; listing may not
expand all theory data, so retain source-data comparisons and focused run results.

## Draft verification boundary — 2026-11-22

The human authorized a static-checked draft on the shared feature-branch checkout
at `a418aa4`, explicitly deferring the pre-edit Windows baseline. Only class traits,
five moves, and this inventory are changed; assertions, fixtures, namespaces,
methods, data, and historical categories are preserved by exact source comparison.
The local Mac has only SDK 8.0.122. No restore, build, discovery, or managed test
execution was attempted. **Windows runtime acceptance remains pending.**

For a genuine before/after gate, the baseline must use the same production sources
as the candidate and only reverse this slice's test organization in a separate
approved checkout. Comparing `a418aa4` against later shared sensor edits would mix
production behavior changes with test organization. Never switch/reset the shared
worker checkout merely to obtain a baseline.
