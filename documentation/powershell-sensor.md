# PowerShell sensor

`PowerShellSensor` subscribes to the Windows PowerShell provider
`a0c1853b-5c40-4b15-8766-3cf1c58f985a` and PowerShell Core provider
`f90714a8-5509-434a-bf6d-b1624c8a19a2`. It models native event **4104, version 1**.
Other events are filtered before payload materialization; unsupported versions,
decoding failures, unhandled provider events and ETW loss are counted in logs.
Provider enablement alone does not prove that the host emits script-block events.

## Enable and build

The sensor defaults to disabled, consistent with optional Windows sensors. Set
`PowerShellSensor` to `True` in the deployed `Wintap.dll.config` user settings and
restart Wintap through your normal operational procedure. The sensor also appears
as `PowerShell` in StateManager's collector settings. The subscription manager
discovers it by name and starts it after process snapshot/kernel initialization.

Deploy `Wintap.dll` and `WintapAPI.dll` from the same publish output; the latter
defines the new payload. The default serializer flushes every 60 seconds. Initial
files appear under the runtime `esper_staging/defaultserializer` directory before
the existing cache pipeline publishes them under `data/raw_sensor/raw_powershell`.

From the repository root:

```powershell
dotnet publish "wintap\Wintap.csproj" -c Release -o "wintap\publish"
```

The sensor owns one uniquely named realtime ETW session. It stops that session
before joining the consumer, releases it after unexpected reader exit, and reports
loss/counters every 30 seconds and on stop. It uses the POC's level 255/all-keyword
subscription; 4104 output filtering does not reduce subscription traffic.

## Event contract and pipeline

Each observation is a `WintapMessage` with `MessageType=PowerShell` and
`ActivityType=EventWritten`. `EventTime` is the ETW timestamp in UTC FILETIME;
`PID` is the ETW emitting process. `ActivityId` and `CorrelationId` retain native
activity/related-activity GUIDs when present. The `PowerShell` payload derives from
`WintapBase` and contains:

| Field | Meaning |
|---|---|
| ProviderGuid | Native Windows PowerShell or PowerShell Core GUID |
| EventId / Version | 4104 / 1 |
| ThreadId | ETW emitting thread |
| MessageNumber / MessageTotal | Native fragment index and total |
| ScriptBlockText | Exact decoded fragment, including Unicode and line endings |
| ScriptBlockId | Native script-block identifier |
| Path | Native path, preserved with original case; may be empty |

The sensor calls `EventChannel.Send`. Canonical `PidHash`, `ProcessName` and
`AgentId` come from the existing processing pipeline, not provider text or a new
identity algorithm. Standard active/event-time history resolution handles exited
hosts and PID reuse. PowerShell participates in the bounded attribution retry queue
for process-registration races; exhaustion follows the existing Unknown-owner
policy. Embedded hosts are accepted without an executable-name filter. No process
creation time is inferred from script-block IDs or ETW activity IDs.

The existing `default.epl`/`DefaultSerializer` path flattens the payload plus the
standard envelope into the `PowerShell` Parquet stream without aggregation. The
diagnostic direct sink retains prefixed payload columns and activity IDs, and still
performs the normal PowerShell owner lookup unless explicitly disabled by diagnostic
configuration. Existing enum ordinals are preserved by appending `PowerShell`.

Fragments and duplicates remain separate observations, including an isolated 3/3
fragment and empty paths/text. There is no assembly, deduplication or execution
count. Script-block observation is not keystroke capture or proof of execution.
Missing logging/provider configuration or ETW loss may leave incomplete coverage.
Payloads with invalid native types/fragment numbering, missing required fields,
more than 64 decoded fields, over 256 KiB of event data, over 65,536 text characters,
or over 32,768 path characters are rejected rather than silently truncated.

## Verification

```powershell
dotnet test "tests\Wintap.Tests\Wintap.Tests.csproj" -c Release --filter "Category=powershell"
```

Tests cover both GUIDs, invalid payloads, fragment/duplicate preservation, startup
classification, real resolver behavior across exited hosts/PID reuse, bounded
registration retries, the shipping default EPL/serializer and Parquet round trips.

From an elevated prompt, an optional isolated native check is:

```powershell
.\devtools\Invoke-PowerShellSensorSmoke.ps1
# To check an existing PowerShell 7 installation:
.\devtools\Invoke-PowerShellSensorSmoke.ps1 -PowerShellExe 'C:\Program Files\PowerShell\7\pwsh.exe'
```

The check builds a temporary harness, launches synthetic activity, validates the
emitting PID and 4104 text marker, and verifies its owned session was released.
It prints counts only, redirects logs into the temporary directory, and does not
change logging policy, register manifests or restart the installed Wintap service.
Its injected sink tests native collection; managed tests verify attribution/ETL.
