#requires -Version 5.1
<#
.SYNOPSIS
Runs an isolated native PowerShell sensor smoke check from an elevated prompt.
.DESCRIPTION
Builds a temporary .NET harness referencing Wintap, enables only its owned ETW
session, and launches synthetic activity. Does not restart Wintap, modify logging
policy, register manifests, or print captured script text. PowerShellExe may name
an existing pwsh.exe to check PowerShell 7. The harness uses an injected sink;
event-time attribution and downstream serialization are covered by the unit tests.
#>
[CmdletBinding()]
param([string]$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe")
$ErrorActionPreference = 'Stop'
$executable = (Get-Item -LiteralPath $PowerShellExe).FullName
$project = Join-Path (Split-Path $PSScriptRoot -Parent) 'wintap\Wintap.csproj'
$smokeRoot = Join-Path ([IO.Path]::GetTempPath()) ('wintap-powershell-smoke-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $smokeRoot
$publishRoot = Join-Path $smokeRoot 'publish'
& dotnet publish $project -c Release -o $publishRoot -p:WarningLevel=0
if ($LASTEXITCODE -ne 0) { throw "Smoke sensor publish failed (exit $LASTEXITCODE)." }
$escapedPublish = [Security.SecurityElement]::Escape($publishRoot)
$csproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="Wintap"><HintPath>$escapedPublish\Wintap.dll</HintPath></Reference>
    <Reference Include="WintapAPI"><HintPath>$escapedPublish\WintapAPI.dll</HintPath></Reference>
    <Reference Include="Microsoft.Diagnostics.Tracing.TraceEvent"><HintPath>$escapedPublish\Microsoft.Diagnostics.Tracing.TraceEvent.dll</HintPath></Reference>
  </ItemGroup>
</Project>
"@
Set-Content -LiteralPath (Join-Path $smokeRoot 'Smoke.csproj') -Value $csproj -Encoding UTF8
Set-Content -LiteralPath (Join-Path $smokeRoot 'Program.cs') -Encoding UTF8 -Value @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Microsoft.Diagnostics.Tracing.Session;

AssemblyLoadContext.Default.Resolving += (_, name) => {
    string path = System.IO.Path.Combine(args[2], name.Name + ".dll");
    return System.IO.File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
};
if (TraceEventSession.IsElevated() != true)
{
    Console.Error.WriteLine("Run the smoke check from an elevated prompt. No ETW session started.");
    return 2;
}
var assembly = typeof(EventChannel).Assembly;
// Redirect logs and disable the base sensor's persisted performance statistics
// in this process only, before instantiating the isolated sensor.
assembly.GetType("gov.llnl.wintap.core.shared.Env").GetMethod("SetDataRoot", BindingFlags.Static | BindingFlags.NonPublic)
    .Invoke(null, new object[] { args[1] });
assembly.GetType("gov.llnl.wintap.core.shared.Env").GetMethod("SetRuntimeRoot", BindingFlags.Static | BindingFlags.NonPublic)
    .Invoke(null, new object[] { args[1] });
var settingsType = assembly.GetType("gov.llnl.wintap.Properties.Settings");
var settings = settingsType.GetProperty("Default").GetValue(null);
settingsType.GetProperty("Profile").SetValue(settings, "Developer");
WintapLogger.Log.Init();
var sensorType = assembly.GetType("gov.llnl.wintap.platform.windows.collect.etw.PowerShellSensor");
var messages = new ConcurrentQueue<WintapMessage>();
var sensor = Activator.CreateInstance(sensorType, BindingFlags.Instance | BindingFlags.NonPublic, null,
    new object[] { new Action<WintapMessage>(messages.Enqueue), new Func<bool>(() => true) }, null);
var before = TraceEventSession.GetActiveSessionNames().ToHashSet();
string marker = "WintapPowerShellSmoke-" + Guid.NewGuid().ToString("N");
int childPid = 0;
bool started = false, matched = false, clean = false;
try
{
    started = (bool)sensorType.GetMethod("Start").Invoke(sensor, null);
    if (!started) throw new InvalidOperationException("Sensor startup failed; inspect isolated logs.");
    Thread.Sleep(1000);
    var info = new ProcessStartInfo(args[0]) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    info.ArgumentList.Add("-NoProfile");
    info.ArgumentList.Add("-NonInteractive");
    info.ArgumentList.Add("-Command");
    info.ArgumentList.Add("Write-Output '" + marker + "'; Start-Sleep -Milliseconds 500");
    using var child = Process.Start(info);
    childPid = child.Id;
    var stdout = child.StandardOutput.ReadToEndAsync();
    var stderr = child.StandardError.ReadToEndAsync();
    if (!child.WaitForExit(15000))
    {
        child.Kill();
        child.WaitForExit();
        throw new TimeoutException("Synthetic child exceeded 15 seconds.");
    }
    stdout.GetAwaiter().GetResult(); stderr.GetAwaiter().GetResult();
    if (child.ExitCode != 0) throw new InvalidOperationException("Synthetic PowerShell child failed.");
    for (int attempt = 0; attempt < 50; attempt++)
    {
        matched = messages.Any(m => m.PID == childPid && m.PowerShell.ScriptBlockText.Contains(marker));
        if (matched) break;
        Thread.Sleep(100);
    }
}
finally
{
    sensorType.GetMethod("Stop").Invoke(sensor, null);
    sensorType.GetMethod("Stop").Invoke(sensor, null);
    clean = !TraceEventSession.GetActiveSessionNames().Except(before).Any(n => n.StartsWith("Wintap-PowerShell-", StringComparison.Ordinal));
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {
        started, matched, childPid, captured4104 = messages.Count(m => m.PID == childPid), ownedSessionReleased = clean
    }));
}
return matched && clean ? 0 : 1;
'@
Write-Host "Isolated build and logs: $smokeRoot"
$smokeProject = Join-Path $smokeRoot 'Smoke.csproj'
# Use the repository feed/signature policy even though the harness is temporary.
& dotnet restore $smokeProject --configfile (Join-Path (Split-Path $PSScriptRoot -Parent) 'NuGet.config')
if ($LASTEXITCODE -ne 0) { throw "Smoke harness restore failed (exit $LASTEXITCODE)." }
& dotnet run --project $smokeProject --no-restore -c Release -p:WarningLevel=0 -- $executable $smokeRoot $publishRoot
if ($LASTEXITCODE -ne 0) { throw "PowerShell sensor smoke check failed (exit $LASTEXITCODE). Inspect $smokeRoot." }
