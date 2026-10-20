using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var lintapDll = GetArg(args, "--lintap-dll")
                ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "wintap", "bin", "Release", "net8.0", "Lintap.dll"));

            var dataRoot = GetArg(args, "--data-root")
                ?? Path.Combine(Path.GetTempPath(), "lintap-smoke-" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(dataRoot);

            var isRoot = string.Equals(Environment.UserName, "root", StringComparison.OrdinalIgnoreCase) ||
                         GetEuid() == 0;

            Console.WriteLine($"SmokeTest: user={Environment.UserName} euid={GetEuid()} isRoot={isRoot}");

            var lintapStartUtc = DateTime.UtcNow;
            Process? lintap = null;
            Process? processTree = null;
            int bashPid = -1;
            int sleepPid = -1;
            try
            {
                // Spawn a long-lived bash->sleep process tree FIRST so the Linux ProcessRundown sensor
                // (which runs at startup) can capture it without requiring eBPF.
                (processTree, bashPid, sleepPid, lintapStartUtc) = StartLongLivedProcessTree(durationSeconds: 60);
                Console.WriteLine($"Spawned pre-start bashPid={bashPid} sleepPid={sleepPid}");

                lintap = StartLintap(lintapDll, dataRoot, isRoot);

                Thread.Sleep(2000);
                Console.WriteLine($"Lintap: pid={lintap.Id} hasExited={lintap.HasExited}");

                try
                {
                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
                    using var resp = http.GetAsync("http://127.0.0.1:8099/").GetAwaiter().GetResult();
                    Console.WriteLine($"Lintap: http://127.0.0.1:8099/ -> {(int)resp.StatusCode}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Lintap: http probe failed: {ex.GetType().Name}: {ex.Message}");
                }

                // For this smoke test we require Lintap to write parquet sensor output
                // under the canonical {DataRoot}/raw_sensor tree.
                var parquetDir = Path.Combine(dataRoot, "raw_sensor");
                if (!WaitForParquet(parquetDir, TimeSpan.FromSeconds(30)))
                {
                    Console.Error.WriteLine($"FAIL: Lintap did not produce any parquet files under {parquetDir} within 30s");
                    Console.Error.WriteLine("  This usually means the data root wasn't applied or ETL/direct-parquet output is not running.");
                    return 2;
                }

                Console.WriteLine($"Using parquet dir: {parquetDir}");

                var parquetRoot = Path.Combine(dataRoot, "raw_sensor");
                var rows = PollProcessRowsFromParquet(parquetRoot, bashPid, sleepPid, lintapStartUtc, TimeSpan.FromSeconds(45));
                StopLintap(lintap);

                if (!rows.TryGetValue(bashPid, out var bashRow))
                {
                    Console.Error.WriteLine($"FAIL: no parquet record found for bash PID {bashPid} (parquet={parquetRoot})");
                    return 3;
                }

                if (!rows.TryGetValue(sleepPid, out var sleepRow))
                {
                    Console.Error.WriteLine($"FAIL: no parquet record found for sleep PID {sleepPid} (parquet={parquetRoot})");
                    return 4;
                }

                if (string.IsNullOrWhiteSpace(bashRow.PidHash))
                {
                    Console.Error.WriteLine("FAIL: bash pid_hash is empty");
                    return 5;
                }

                if (sleepRow.ParentPid != bashPid)
                {
                    Console.Error.WriteLine($"FAIL: sleep parent_pid expected {bashPid} got {sleepRow.ParentPid}");
                    return 7;
                }

                if (string.IsNullOrWhiteSpace(sleepRow.ParentPidHash))
                {
                    Console.WriteLine("WARN: parent_pid_hash not present in parquet schema; skipping parent hash validation");
                }
                else if (!string.Equals(sleepRow.ParentPidHash, bashRow.PidHash, StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine("FAIL: sleep parent_pid_hash does not match bash pid_hash");
                    Console.Error.WriteLine($"  sleep.parent_pid_hash={sleepRow.ParentPidHash}");
                    Console.Error.WriteLine($"  bash.pid_hash={bashRow.PidHash}");
                    return 8;
                }

                Console.WriteLine("OK: process smoke test passed");
                Console.WriteLine($"  DataRoot: {dataRoot}");
                Console.WriteLine($"  ParquetRoot: {parquetRoot}");
                Console.WriteLine($"  bash:  pid={bashPid} pid_hash={bashRow.PidHash}");
                Console.WriteLine($"  sleep: pid={sleepPid} parent_pid={sleepRow.ParentPid} parent_pid_hash={(string.IsNullOrEmpty(sleepRow.ParentPidHash) ? "<missing>" : sleepRow.ParentPidHash)}");
                return 0;
            }
            finally
            {
                if (processTree != null)
                {
                    try
                    {
                        if (!processTree.HasExited)
                        {
                            processTree.Kill(entireProcessTree: true);
                        }
                    }
                    catch { }
                    processTree.Dispose();
                }

                if (lintap != null)
                {
                    StopLintap(lintap);
                    lintap.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL: unhandled exception");
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static Process StartLintap(string lintapDll, string dataRoot, bool isRoot)
{
    if (!File.Exists(lintapDll))
    {
        throw new FileNotFoundException($"Lintap dll not found: {lintapDll}");
    }

    var psi = new ProcessStartInfo("dotnet")
    {
        Arguments = Quote(lintapDll),
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };

    // Avoid using the repo directory (often a shared mount) as the content root.
    // ASP.NET defaults ContentRootPath to the working directory.
    psi.WorkingDirectory = Path.GetDirectoryName(lintapDll) ?? Path.GetTempPath();

    // Create a minimal ETLConfig.json for this run so Lintap picks up the desired DataRoot
    var tempConfig = new
    {
        DataRoot = dataRoot,
        DisableMCP = true,
        DisableDuckDBUI = true,
        DisableETL = true,
        EnableDirectParquet = true,
        DirectParquetFlushSeconds = 2,
        SkipEsperSend = true,
        SkipProcessResolve = true,
        SkipParentProcessResolve = true,
        SkipProcessRegister = true,
        DisableSensors = false,
        Execve = false,
        Exit = false,
        Clone = false,
        Network = false,
        FileOps = false,
        ProcessRundown = true
    };
    string tempConfigPath = Path.Combine(Path.GetTempPath(), $"etlconfig-{Guid.NewGuid():N}.json");
    File.WriteAllText(tempConfigPath, JsonSerializer.Serialize(tempConfig));
    psi.Environment["WINTAP_CONFIG_PATH"] = tempConfigPath;

    // No additional env vars; config file controls behavior.

    var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start Lintap process");

    // Drain output asynchronously to avoid deadlocks.
    _ = Task.Run(() => Drain(p.StandardOutput, "lintap:out"));
    _ = Task.Run(() => Drain(p.StandardError, "lintap:err"));

    return p;
}

    private static void StopLintap(Process lintap)
{
    try
    {
        if (lintap.HasExited)
        {
            return;
        }

        // Best-effort graceful shutdown via SIGINT.
        try
        {
            using var killer = Process.Start(new ProcessStartInfo("bash")
            {
                Arguments = "-c " + Quote($"kill -INT {lintap.Id} 2>/dev/null || true"),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            killer?.WaitForExit(2000);
        }
        catch
        {
            // ignore
        }

        if (!lintap.WaitForExit(10_000))
        {
            lintap.Kill(entireProcessTree: true);
        }
    }
    catch
    {
        // ignore
    }
}

    private static (int bashPid, int sleepPid, DateTime startUtc, DateTime endUtc) SpawnProcessTree()
{
    var startUtc = DateTime.UtcNow;
    var output = new StringBuilder();

    using var p = new Process();
    p.StartInfo = new ProcessStartInfo("bash")
    {
        Arguments = "-c " + Quote("echo BASH_PID=$$; sleep 0.2 & echo SLEEP_PID=$!; wait"),
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };

    p.Start();
    var stdout = p.StandardOutput.ReadToEnd();
    var stderr = p.StandardError.ReadToEnd();
    p.WaitForExit();
    var endUtc = DateTime.UtcNow;

    output.AppendLine(stdout);
    if (!string.IsNullOrWhiteSpace(stderr))
    {
        output.AppendLine(stderr);
    }

    int? bashPid = null;
    int? sleepPid = null;
    foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (line.StartsWith("BASH_PID=", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(line.Substring("BASH_PID=".Length), out var v1))
        {
            bashPid = v1;
        }
        if (line.StartsWith("SLEEP_PID=", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(line.Substring("SLEEP_PID=".Length), out var v2))
        {
            sleepPid = v2;
        }
    }

    if (bashPid is null || sleepPid is null)
    {
        throw new InvalidOperationException("Failed to parse process PIDs from bash output:\n" + output);
    }

    return (bashPid.Value, sleepPid.Value, startUtc, endUtc);
}

    private static (Process proc, int bashPid, int sleepPid, DateTime startUtc) StartLongLivedProcessTree(int durationSeconds)
    {
        var startUtc = DateTime.UtcNow;
        var psi = new ProcessStartInfo("bash")
        {
            Arguments = "-c " + Quote($"echo BASH_PID=$$; sleep {durationSeconds} & echo CHILD_PID=$!; wait"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start bash process tree");

        int bashPid = p.Id;
        int childPid = -1;

        // Read a few initial lines to capture CHILD_PID.
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline && childPid <= 0)
        {
            var line = p.StandardOutput.ReadLine();
            if (line == null) break;
            line = line.Trim();
            if (line.StartsWith("CHILD_PID=", StringComparison.OrdinalIgnoreCase))
            {
                int.TryParse(line.Split('=', 2)[1], out childPid);
            }
        }

        // Drain remaining output asynchronously.
        _ = Task.Run(() => Drain(p.StandardOutput, "tree:out"));
        _ = Task.Run(() => Drain(p.StandardError, "tree:err"));

        if (childPid <= 0)
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new InvalidOperationException("Failed to parse CHILD_PID from bash output");
        }

        return (p, bashPid, childPid, startUtc);
    }

    private static bool WaitForParquet(string parquetDir, TimeSpan timeout)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            try
            {
                if (Directory.Exists(parquetDir))
                {
                    var files = Directory.EnumerateFiles(parquetDir, "*.parquet", SearchOption.AllDirectories);
                    if (files.Any())
                        return true;
                }
            }
            catch { }

            Thread.Sleep(500);
        }

        return false;
    }

    internal sealed record ProcessRecordRow(
        string PidHash,
        string ParentPidHash,
        int Pid,
        int ParentPid);

    private static Dictionary<int, ProcessRecordRow> PollProcessRowsFromParquet(string parquetRoot, int bashPid, int sleepPid, DateTime startUtc, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var files = FindCandidateParquetFiles(parquetRoot, startUtc);
                if (files.Count == 0)
                {
                    Thread.Sleep(500);
                    continue;
                }

                var cols = DetectColumnNames(files);
                var rows = QueryParquet(files, new[] { bashPid, sleepPid }, cols);
                if (rows.TryGetValue(bashPid, out _) && rows.TryGetValue(sleepPid, out _))
                {
                    return rows;
                }
            }
            catch
            {
                // keep polling
            }

            Thread.Sleep(500);
        }

        return new Dictionary<int, ProcessRecordRow>();
    }

    private static List<string> FindCandidateParquetFiles(string parquetRoot, DateTime startUtc)
    {
        if (!Directory.Exists(parquetRoot))
        {
            return new List<string>();
        }

        var cutoff = startUtc.AddSeconds(-30);
        var files = new List<string>();
        foreach (var path in Directory.EnumerateFiles(parquetRoot, "*.parquet", SearchOption.AllDirectories))
        {
            if (path.EndsWith(".active", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            try
            {
                if (File.GetLastWriteTimeUtc(path) >= cutoff)
                {
                    files.Add(path);
                }
            }
            catch { }
        }

        var processFiles = files.Where(p => p.ToLowerInvariant().Contains("process")).ToList();
        return processFiles.Count > 0 ? processFiles : files;
    }

    private static Dictionary<string, string> DetectColumnNames(List<string> files)
    {
        var probe = RunDuckDbJson(BuildProbeSql(files));
        var cols = probe.Count > 0 ? new HashSet<string>(probe[0].Keys) : new HashSet<string>();

        string pick(string fallback, params string[] candidates)
        {
            foreach (var c in candidates)
            {
                if (cols.Contains(c)) return c;
            }
            return fallback;
        }

        var parentPidHash = pick(string.Empty, "Process_ParentPidHash", "ParentPidHash");

        return new Dictionary<string, string>
        {
            ["pid"] = pick("PID", "PID"),
            ["message_type"] = pick("MessageType", "MessageType"),
            ["activity_type"] = pick("ActivityType", "ActivityType"),
            ["pid_hash"] = pick("PidHash", "PidHash"),
            ["parent_pid"] = pick("ParentPid", "Process_ParentPID", "ParentPid"),
            ["parent_pid_hash"] = parentPidHash,
            ["captured_ts"] = pick("EventTime", "CapturedUtc", "EventTime")
        };
    }

    private static Dictionary<int, ProcessRecordRow> QueryParquet(List<string> files, int[] pids, Dictionary<string, string> cols)
    {
        var sql = BuildProcessQuery(files, pids, cols);
        var rows = RunDuckDbJson(sql);

        var result = new Dictionary<int, ProcessRecordRow>();
        foreach (var row in rows)
        {
            if (!row.TryGetValue("pid", out var pidEl) || pidEl.ValueKind != JsonValueKind.Number)
            {
                continue;
            }
            int pid = pidEl.GetInt32();
            row.TryGetValue("pid_hash", out var pidHashEl);
            row.TryGetValue("parent_pid", out var parentPidEl);
            row.TryGetValue("parent_pid_hash", out var parentPidHashEl);
            int parentPid = parentPidEl.ValueKind == JsonValueKind.Number ? parentPidEl.GetInt32() : 0;
            string pidHash = pidHashEl.ValueKind == JsonValueKind.String ? pidHashEl.GetString() ?? "" : "";
            string parentPidHash = parentPidHashEl.ValueKind == JsonValueKind.String ? parentPidHashEl.GetString() ?? "" : "";
            result[pid] = new ProcessRecordRow(pidHash, parentPidHash, pid, parentPid);
        }
        return result;
    }

    private static string BuildProbeSql(List<string> files)
    {
        string fileList = string.Join(", ", files.Select(f => SqlString(f)));
        return $"WITH data AS (SELECT * FROM read_parquet([{fileList}], union_by_name=true)) SELECT * FROM data LIMIT 1;";
    }

    private static string BuildProcessQuery(List<string> files, int[] pids, Dictionary<string, string> cols)
    {
        string fileList = string.Join(", ", files.Select(f => SqlString(f)));
        string pidList = string.Join(",", pids.Select(p => p.ToString()));
        string parentPidHashExpr = string.IsNullOrWhiteSpace(cols["parent_pid_hash"])
            ? "CAST(NULL AS VARCHAR) AS parent_pid_hash"
            : $"CAST({cols["parent_pid_hash"]} AS VARCHAR) AS parent_pid_hash";

        return $@"
WITH data AS (
    SELECT * FROM read_parquet([{fileList}], union_by_name=true)
)
SELECT
    TRY_CAST({cols["pid"]} AS INTEGER) AS pid,
    CAST({cols["pid_hash"]} AS VARCHAR) AS pid_hash,
    TRY_CAST({cols["parent_pid"]} AS INTEGER) AS parent_pid,
    {parentPidHashExpr},
    TRY_CAST({cols["captured_ts"]} AS TIMESTAMP) AS captured_utc
FROM data
WHERE TRY_CAST({cols["pid"]} AS INTEGER) IN ({pidList})
  AND lower(CAST({cols["message_type"]} AS VARCHAR)) LIKE 'process%'
ORDER BY captured_utc DESC NULLS LAST;";
    }

    private static List<Dictionary<string, JsonElement>> RunDuckDbJson(string sql)
    {
        var psi = new ProcessStartInfo("duckdb")
        {
            Arguments = "-json -c " + Quote(sql),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start duckdb CLI");
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException("duckdb CLI failed: " + stderr);
        }

        stdout = stdout.Trim();
        if (string.IsNullOrEmpty(stdout))
        {
            return new List<Dictionary<string, JsonElement>>();
        }

        return JsonSerializer.Deserialize<List<Dictionary<string, JsonElement>>>(stdout) ?? new List<Dictionary<string, JsonElement>>();
    }

    private static string SqlString(string value) => "'" + value.Replace("'", "''") + "'";

    private static void Drain(StreamReader reader, string prefix)
{
    try
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            Console.WriteLine($"{prefix}> {line}");
        }
    }
    catch
    {
        // ignore
    }
}

    private static string? GetArg(string[] args, string name)
{
    for (int i = 0; i < args.Length; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
        {
            return args[i + 1];
        }
    }
    return null;
}

    private static bool WaitForFile(string path, TimeSpan timeout)
{
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < timeout)
    {
        if (File.Exists(path))
        {
            return true;
        }
        Thread.Sleep(200);
    }
    return false;
}

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static int GetEuid()
{
    try
    {
        return (int)Marshal.GetDelegateForFunctionPointer<GeteuidDelegate>(
            NativeLibrary.GetExport(NativeLibrary.Load("libc"), "geteuid"))();
    }
    catch
    {
        return -1;
    }
}

internal delegate uint GeteuidDelegate();
}
