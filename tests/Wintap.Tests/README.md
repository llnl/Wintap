# Wintap.Tests

Windows-targeted xUnit assembly (`net10.0-windows10.0.17763.0`). Use **Windows and
a stable .NET 10 SDK** for native Windows verification.
`global.json` permits major-10 roll-forward from minimum 10.0.100 and excludes
prereleases. Record actual `dotnet --version` in verification evidence.
macOS and Linux testing of the feature branch is complete. That evidence is separate
from native Windows verification; linked Linux helpers in this assembly alone do
not establish Linux collector coverage. See `tests/Lintap.Tests/README.md` for the
Linux-focused assembly.

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

Counts describe this source slice, not full-suite pass totals.
The emission neighbor consumes
`WindowsFilePathNormalizerTests.Map`; include it whenever checking the moves, but
do not classify it as a unit solely because it shares that fixture.

Selected cases use synthetic inputs/injected callbacks; they do not launch a
collector, generate traffic, or read external datasets. Synthetic tests still
reference the Windows agent and its runtime/native dependencies.

Other tests include source guards, DuckDB/Esper fixtures and native command probes.
Unfiltered `dotnet test` includes native/integration cases; missing traits do not
indicate safe or portable execution.

## Focused Windows verification

Run from the repository root. Record the revision, dirty state, actual SDK,
configuration and results. Use locked restore; do not regenerate lockfiles merely
to make a test run pass.

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

Use a **120-second ceiling per command** initially. Record timeouts, skips,
discovery failures and zero matches. Discovery can evaluate unrelated MemberData;
listing is not a test pass. Use `--no-build` only with freshly built matching sources.

Expected selections are 84 focused cases (including the neighbor) and 77
classified cases in exactly the five reviewed classes. Confirm actual adapter
discovery/execution and existing Category selections on Windows; listing may not
expand all theory data, so retain source-data comparisons and focused run results.

## Verification boundary

macOS and Linux feature-branch testing is complete; the earlier static-only draft
boundary is superseded. Native Windows acceptance remains a separate gate.

For test-organization comparisons, hold production sources constant. Do not compare
an older baseline containing different sensor behavior or reset a shared checkout.
