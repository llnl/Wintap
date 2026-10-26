using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Parquet;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    public class ParquetMigrationTests
    {
        [Fact]
        public async Task DynamicTelemetryPreservesNullsTimestampsAndIdentifiersAcrossRoundTrip()
        {
            var schema = new ParquetSchema(
                new DataField<long>("EventTime"),
                new DataField<int>("PID"),
                new DataField<string>("PidHash"),
                new DataField<string>("ParentPidHash"));
            var rows = new List<IDictionary<string, object>>
            {
                new Dictionary<string, object>
                {
                    ["EventTime"] = 133700000000000000L,
                    ["PID"] = 42,
                    ["PidHash"] = "D41D8CD98F00B204E9800998ECF8427E",
                    ["ParentPidHash"] = null
                }
            };
            using var original = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(rows, schema, original,
                new ParquetOptions { CompressionMethod = CompressionMethod.Snappy });
            original.Position = 0;
            var firstRead = await ParquetSerializer.DeserializeUntypedAsync(original);
            using var rewritten = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(
                firstRead.Data.Cast<IDictionary<string, object>>().ToList(), firstRead.Schema, rewritten);
            rewritten.Position = 0;
            var secondRead = await ParquetSerializer.DeserializeUntypedAsync(rewritten);
            Assert.Single(secondRead.Data);
            Assert.Contains(secondRead.Schema.GetDataFields(), field => field.Name == "ParentPidHash");
            foreach (var field in rows[0])
            {
                secondRead.Data[0].TryGetValue(field.Key, out var value);
                Assert.Equal(field.Value, value);
            }
        }
    }
}
