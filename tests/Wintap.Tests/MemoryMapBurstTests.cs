using System;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Threading;
using DuckDB.NET.Data;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.infrastructure;
using Xunit;
using static gov.llnl.wintap.collect.models.WintapMessage;

namespace Wintap.Tests
{
    // Run explicitly in an isolated test process: ETL configuration and Esper
    // are process-wide. Both cases exercise the actual serializer and writer.
    [Collection("MemoryMap isolated ETL")]
    public class MemoryMapBurstTests
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void SnapshotBurstPreservesPayloadAndAttribution(bool legacy)
        {
            string root = Path.Combine(Path.GetTempPath(), "wintap-memorymap-" + Guid.NewGuid());
            Directory.CreateDirectory(root);
            string configPath = Path.Combine(Path.GetDirectoryName(typeof(DefaultSerializer).Assembly.Location), "ETLConfig.json");
            byte[] original = File.Exists(configPath) ? File.ReadAllBytes(configPath) : null;
            string oldCapacity = Environment.GetEnvironmentVariable("WINTAP_ETL_MAX_QUEUE_EVENTS");
            string oldDataRoot = Env.FileDataRoot, oldRuntimeRoot = Env.FileRuntimeRoot;
            DefaultSerializer serializer = null;
            string marker = Guid.NewGuid().ToString();
            string[] existingDeployments = Array.Empty<string>();
            try
            {
                Environment.SetEnvironmentVariable("WINTAP_ETL_MAX_QUEUE_EVENTS", "10000");
                Env.SetDataRoot(root);
                Env.SetRuntimeRoot(root);
                existingDeployments = EventChannel.EsperRuntime.DeploymentService.Deployments;
                File.WriteAllText(configPath, legacy
                    ? "{\"SerializationIntervalSec\":60,\"Serializers\":{\"defaultserializer\":{\"UseDedicatedWorker\":false,\"HighWaterEvents\":0}}}"
                    : "{\"SerializationIntervalSec\":60}");
                serializer = new DefaultSerializer("gov.llnl.wintap.core.etl.esper.default.epl");
                DateTime time = DateTime.UtcNow;
                for (int i = 0; i < 30000; i++)
                {
                    serializer.Listen(new WintapMessage(time, 4242, MessageTypeEnum.MemoryMap) {
                        PidHash = marker, ProcessName = "memorymap-burst.exe", AgentId = "burst-agent",
                        ActivityType = ActivityTypeEnum.MemCommit,
                        MemoryMap = new MemoryMapData {
                            BaseAddress = (i * 4096L).ToString("X"), AllocationBaseAddress = "0",
                            RegionSize = 4096, Description = "region-" + i,
                            PageType = PageTypeEnum.MEM_PRIVATE, MZHeaderPresent = i % 2 == 0
                        }
                    });
                }
                // Drain the final partial batch without waiting for the interval.
                var worker = typeof(Serializer).GetField("flushWorker", BindingFlags.NonPublic | BindingFlags.Instance);
                (worker.GetValue(serializer) as IDisposable)?.Dispose();
                typeof(Serializer).GetMethod("FlushToDisk", BindingFlags.NonPublic | BindingFlags.Instance)
                    .Invoke(serializer, new object[] { "test_final" });
                using var db = new DuckDBConnection("DataSource=:memory:");
                db.Open();
                long expected = legacy ? 10000 : 30000;
                long count = 0;
                Assert.True(SpinWait.SpinUntil(() => {
                    var files = Directory.GetFiles(root, "memorymap-*.parquet", SearchOption.AllDirectories);
                    if (files.Length == 0) return false;
                    using var cmd = db.CreateCommand();
                    string paths = string.Join(",", Array.ConvertAll(files, p => "'" + p.Replace("\\", "/").Replace("'", "''") + "'"));
                    cmd.CommandText = "SELECT COUNT(*) FROM read_parquet([" + paths + "]) WHERE PidHash='" + marker + "'";
                    count = Convert.ToInt64(cmd.ExecuteScalar());
                    return count >= expected;
                }, TimeSpan.FromSeconds(30)), $"Only {count}/{expected} rows; evidence: {root}");
                Assert.Equal(expected, count);
                var retained = Directory.GetFiles(root, "memorymap-*.parquet", SearchOption.AllDirectories);
                string inputs = string.Join(",", Array.ConvertAll(retained, p => "'" + p.Replace("\\", "/") + "'"));
                using var check = db.CreateCommand();
                check.CommandText = "SELECT COUNT(DISTINCT BaseAddress), CAST(SUM(CASE WHEN PID=4242 AND AgentId='burst-agent' AND ProcessName='memorymap-burst.exe' AND RegionSize=4096 AND ActivityType='MemCommit' AND PageType='MEM_PRIVATE' AND AllocationBaseAddress='0' AND BaseAddress=printf('%X', CAST(substring(Description,8) AS BIGINT)*4096) AND MZHeaderPresent=(CAST(substring(Description,8) AS BIGINT)%2=0) AND EventTime=" + time.ToFileTimeUtc() + " THEN 0 ELSE 1 END) AS BIGINT) FROM read_parquet([" + inputs + "]) WHERE PidHash='" + marker + "'";
                using var reader = check.ExecuteReader();
                Assert.True(reader.Read());
                Assert.Equal(expected, Convert.ToInt64(reader.GetValue(0)));
                Assert.Equal(0, Convert.ToInt64(reader.GetValue(1)));
                long dropped = (long)typeof(Serializer).GetField("droppedDueToBacklog", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(serializer);
                Assert.Equal(legacy ? 20000 : 0, dropped);
                File.WriteAllText(Path.Combine(root, "result.txt"), $"legacy={legacy},sent=30000,retained={count},dropped={dropped}");
            }
            finally
            {
                if (serializer != null) {
                    serializer.Stop();
                    (typeof(Serializer).GetField("flushWorker", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(serializer) as IDisposable)?.Dispose();
                }
                foreach (string deployment in EventChannel.EsperRuntime.DeploymentService.Deployments.Except(existingDeployments))
                    EventChannel.EsperRuntime.DeploymentService.Undeploy(deployment);
                typeof(Serializer).GetField("_esperContextRegistered", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, 0);
                if (original != null) File.WriteAllBytes(configPath, original);
                else File.Delete(configPath);
                Environment.SetEnvironmentVariable("WINTAP_ETL_MAX_QUEUE_EVENTS", oldCapacity);
                Env.SetDataRoot(oldDataRoot);
                Env.SetRuntimeRoot(oldRuntimeRoot);
            }
        }
    }

    [CollectionDefinition("MemoryMap isolated ETL", DisableParallelization = true)]
    public class MemoryMapIsolatedCollection { }
}

