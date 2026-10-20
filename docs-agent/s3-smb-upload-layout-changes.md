# Agent Notes: S3/SMB Upload Layout Changes

Date: 2026-05-29

## Purpose

This note captures the work done to update Wintap ETL upload adapters so they support the newer canonical `raw_sensor` directory layout. It is intended as restart context for a future coding-agent session.

## High-level requirement

Wintap now materializes parquet into a local layout rooted at `raw_sensor`, for example:

```text
<data-root>/parquet/raw_sensor/raw_process/dayPK=20260529/hourPK=13/<file>.parquet
<data-root>/parquet/raw_sensor/raw_process_conn_incr/dayPK=20260529/hourPK=13/protoPK=tcp/<file>.parquet
```

Uploaders should preserve that relative layout at the destination. `raw_sensor` should be the top-level folder/key unless an explicit configured prefix/path is supplied.

## Relevant architecture/context

### ETL config loading

Runtime config is read by:

```text
wintap/wintap/core/etl/shared/Utilities.cs
```

`Utilities.GetETLConfig()` reads:

```text
<Assembly.GetExecutingAssembly().Location>/ETLConfig.json
```

Source config is:

```text
wintap/wintap/core/etl/ETLConfig.json
```

Build item metadata was updated in:

```text
wintap/wintap/Wintap.Common.props
```

to copy/link it into the output as `ETLConfig.json`.

### Upload adapter loading

Upload adapters are not the MEF plugin mechanism. They are ETL adapters loaded by name in:

```text
wintap/wintap/core/etl/load/CacheManager.cs
```

The adapter type is resolved as:

```csharp
Type.GetType("gov.llnl.wintap.core.etl.load.adapters." + u.Name)
```

Adapters implement:

```text
wintap/wintap/core/etl/load/interfaces/IUpload.cs
```

### Local raw_sensor writing

Canonical local output is produced by:

```text
wintap/wintap/core/etl/load/RawSensorWriter.cs
```

It writes under:

```text
Paths.ParquetDataPath/raw_sensor/<event_type>/dayPK=<yyyyMMdd>/hourPK=<HH>/[protoPK=tcp|udp]/<file>.parquet
```

`CacheManager` already scans files recursively under `raw_sensor`.

## Changed files

### `wintap/wintap/core/etl/load/adapters/base/Uploader.cs`

Added shared helper logic for upload destination paths:

- `getS3ObjectNameForFile(string localFile, Dictionary<string, string> parameters)`
- `getFileShareRelativePathForFile(string localFile, Dictionary<string, string> parameters)`
- `getParameter(...)`

Behavior:

1. Computes the file path relative to `Paths.ParquetDataPath` when possible.
2. If that fails, searches the full path for `/raw_sensor/` and returns from `raw_sensor` onward.
3. If that also fails, logs a warning and falls back to just the filename.
4. For S3, normalizes separators to `/`.
5. Optional configured destination prefix is supported using the first non-empty value from:
   - `KeyPrefix`
   - `Path`
   - `ObjectPrefix`

Example:

```text
local:
  /var/log/lintap/data/raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet

S3 key, no prefix:
  raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet

S3 key, KeyPrefix=my-prefix:
  my-prefix/raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet
```

The old `Uploader.getS3ObjectNameForFile` rebuilt a legacy key from only the filename and hardcoded `v3/raw_sensor/.../uploadedDPK=.../uploadedHPK=...`. That has been replaced.

### `wintap/wintap/core/etl/load/adapters/S3Adapter.cs`

Updated S3 behavior:

- Calls `getS3ObjectNameForFile(localFileInfo.FullName, parameters)` instead of passing only the filename.
- Supports static credentials from config:
  - `AccessKey`
  - `SecretKey`
  - optional `SessionToken`
- Falls back to `InstanceProfileAWSCredentials` when static credentials are absent.
- Supports custom S3/S3-compatible endpoints:
  - `ServiceURL`
  - fallback alias `Endpoint`
- Supports `RegionEndpoint` for standard AWS regions and as `AuthenticationRegion` when `ServiceURL` is used.
- Supports `ForcePathStyle` for MinIO/path-style S3-compatible deployments.

Practical tip (S3-compatible/on-prem): if you see DNS errors that look like `Name or service not known (<bucket>.<host>:<port>)`, the SDK is trying virtual-hosted-style bucket addressing. Set `ForcePathStyle` to `"true"` so requests go to `http(s)://<host>:<port>/<bucket>/<key>` instead.
- Uses `client?.Dispose()` and nulls the client in `PostUpload()`.
- Calls `updateSessionStats()` on successful upload.

Important caveat: do **not** call `UploadCompleted?.Invoke(...)` from individual uploaders unless `CacheManager` semantics are revisited. `CacheManager` currently subscribes to `UploadCompleted` and deletes the local file when the event fires. If more than one uploader is enabled, firing this event from one uploader could delete the file before the other uploader receives it. This was briefly added and then removed.

### `wintap/wintap/core/etl/load/adapters/SMBFileShareAdapter.cs`

Updated SMB behavior:

- Preserves the same `raw_sensor/...` relative layout under the configured UNC share.
- Creates destination directories as needed.
- Uses optional `Path`, `KeyPrefix`, or `ObjectPrefix` prefix via shared `Uploader` helper.
- Copies with overwrite enabled: `fileInfo.CopyTo(destinationFile, true)`.

Example:

```text
local:
  <data-root>/parquet/raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet

UNCPath=\\server\share, no Path:
  \\server\share\raw_sensor\raw_process\dayPK=20260529\hourPK=13\file.parquet

UNCPath=\\server\share, Path=wintap-prod:
  \\server\share\wintap-prod\raw_sensor\raw_process\dayPK=20260529\hourPK=13\file.parquet
```

### `wintap/wintap/core/etl/ETLConfig.json`

Updated adapter properties.

SMB block now has:

```json
{
  "Properties": {
    "UNCPath": "",
    "Path": ""
  },
  "Name": "SMBFileShareAdapter",
  "Enabled": false
}
```

S3 block now has:

```json
{
  "Properties": {
    "Bucket": "",
    "RegionEndpoint": "",
    "ServiceURL": "",
    "Endpoint": "",
    "AccessKey": "",
    "SecretKey": "",
    "SessionToken": "",
    "KeyPrefix": "",
    "ForcePathStyle": "false"
  },
  "Name": "S3Adapter",
  "Enabled": false
}
```

Also removed a trailing comma after `WriteToParquet` so the file is strict JSON.

### `wintap/wintap/Wintap.Common.props`

Changed the ETL config item from:

```xml
<None Include="core\etl\ETLConfig.json" />
```

to:

```xml
<None Include="core\etl\ETLConfig.json">
  <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  <Link>ETLConfig.json</Link>
</None>
```

This aligns with `Utilities.GetETLConfig()`, which reads `ETLConfig.json` beside the executing assembly.

## Validation performed

Command run:

```bash
dotnet restore wintap/wintap/Lintap.csproj && dotnet build wintap/wintap/Lintap.csproj --no-restore
```

Result:

```text
Build succeeded
499 Warning(s)
0 Error(s)
```

Warnings were existing/general project warnings, mostly XML documentation and cross-platform analyzer warnings for Windows-only APIs in the Linux build.

## Notes for future restart

1. Work was done in the `wintap` repo under `/Users/johnson30/git-lintap/wintap`.
2. There are unrelated modified files in the working tree outside this task. Do not assume all `git status` changes belong to this work. Relevant changes for this task are limited to:
   - `wintap/Wintap.Common.props`
   - `wintap/core/etl/ETLConfig.json`
   - `wintap/core/etl/load/adapters/base/Uploader.cs`
   - `wintap/core/etl/load/adapters/S3Adapter.cs`
   - `wintap/core/etl/load/adapters/SMBFileShareAdapter.cs`
   - this docs directory
3. The user asked to use rate-limited/resilient-fetch behavior due to `429 Portkey Error`. Continue with sequential, minimal tool calls; avoid parallel tool calls and repeated broad searches.
4. If adding tests later, good candidates are pure unit tests around destination path generation. The helper methods are currently `protected`/private in `Uploader`, so testing may require a small test subclass or changing visibility intentionally.
5. Potential future improvement: centralize deletion semantics in `CacheManager` so files are deleted only after all enabled uploaders succeed. Current behavior has `UploadCompleted` but uploaders do not fire it after this change to avoid premature deletion when multiple uploaders are enabled.
