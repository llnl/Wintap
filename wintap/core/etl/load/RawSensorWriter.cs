using DuckDB.NET.Data;
using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.infrastructure;
using System;
using System.IO;

namespace gov.llnl.wintap.core.etl.load
{
    /// <summary>
    /// Materializes serializer parquet files directly into the canonical raw_sensor
    /// partition layout used by downstream DBT processing. This skips the legacy
    /// intermediate merged directory and uses DuckDB as the parquet writer.
    /// </summary>
    internal static class RawSensorWriter
    {
        internal static void MaterializeFromParquetGlob(string sourceParquetGlob, string outputFileName)
        {
            if (string.IsNullOrWhiteSpace(sourceParquetGlob) || string.IsNullOrWhiteSpace(outputFileName))
            {
                return;
            }

            if (!outputFileName.EndsWith(".parquet", StringComparison.OrdinalIgnoreCase))
            {
                outputFileName += ".parquet";
            }

            ParsedMergedFile parsed = ParseMergedFileName(outputFileName);
            DateTime captureTimeUtc = DateTime.FromFileTimeUtc(parsed.DataCaptureFileTimeUtc);

            string dayPartition = captureTimeUtc.ToString("yyyyMMdd");
            string hourPartition = captureTimeUtc.ToString("HH");
            string outputEventType = MapEventType(parsed.EventType, out string protocol);

            string outputDirectory = Path.Combine(
                Paths.ParquetDataPath,
                "raw_sensor",
                outputEventType,
                $"dayPK={dayPartition}",
                $"hourPK={hourPartition}");

            if (!string.IsNullOrWhiteSpace(protocol))
            {
                outputDirectory = Path.Combine(outputDirectory, $"protoPK={protocol}");
            }

            Directory.CreateDirectory(outputDirectory);

            string destinationFile = Path.Combine(outputDirectory, outputFileName);
            WriteParquetWithDuckDB(sourceParquetGlob, destinationFile);

            WintapLogger.Log.Append($"Materialized raw_sensor parquet: {destinationFile}", LogLevel.Info);
        }

        internal static void MaterializeFromMergedFile(FileInfo mergedFile)
        {
            if (mergedFile == null || !mergedFile.Exists || !mergedFile.Name.EndsWith(".parquet", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            MaterializeFromParquetGlob(mergedFile.FullName, mergedFile.Name);
        }

        private static ParsedMergedFile ParseMergedFileName(string fileName)
        {
            string nameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);

            // Legacy format: hostname=event_type+filetime.parquet
            if (nameWithoutExtension.Contains("="))
            {
                string[] hostSplit = nameWithoutExtension.Split(new[] { '=' }, 2);
                string[] eventAndTime = hostSplit[1].Split('+');
                if (eventAndTime.Length < 2)
                {
                    throw new FormatException($"Could not parse legacy merged parquet filename: {fileName}");
                }

                string eventType = string.Join("+", eventAndTime, 0, eventAndTime.Length - 1);
                long fileTime = long.Parse(eventAndTime[eventAndTime.Length - 1]);
                return new ParsedMergedFile(hostSplit[0], eventType, fileTime);
            }

            // New format: hostname+event_type+filetime.parquet
            string[] parts = nameWithoutExtension.Split('+');
            if (parts.Length < 3)
            {
                throw new FormatException($"Could not parse merged parquet filename: {fileName}");
            }

            string hostname = parts[0];
            string eventTypeNew = parts[1];
            long captureFileTime = long.Parse(parts[2]);
            return new ParsedMergedFile(hostname, eventTypeNew, captureFileTime);
        }

        private static string MapEventType(string eventType, out string protocol)
        {
            protocol = null;
            string normalized = eventType.ToLowerInvariant();

            if (normalized.Contains("tcp"))
            {
                protocol = "tcp";
                return "raw_process_conn_incr";
            }

            if (normalized.Contains("udp"))
            {
                protocol = "udp";
                return "raw_process_conn_incr";
            }

            switch (normalized)
            {
                case "raw_host_sensor":
                    return "raw_host";
                case "raw_macip_sensor":
                    return "raw_macip";
                case "raw_file":
                    return "raw_process_file";
                case "raw_processstop":
                    return "raw_process";
                case "raw_registry":
                    return "raw_process_registry";
                default:
                    return normalized;
            }
        }

        private static void WriteParquetWithDuckDB(string sourceParquetGlob, string destinationFile)
        {
            string tempDestinationFile = destinationFile + ".active";

            if (File.Exists(tempDestinationFile))
            {
                File.Delete(tempDestinationFile);
            }

            using (var duckDBConnection = new DuckDBConnection("Data Source=:memory:"))
            {
                duckDBConnection.Open();
                using (var command = duckDBConnection.CreateCommand())
                {
                    command.CommandText = $"COPY (SELECT * FROM read_parquet('{DuckDBPath(sourceParquetGlob)}')) TO '{DuckDBPath(tempDestinationFile)}' (FORMAT PARQUET, COMPRESSION SNAPPY);";
                    WintapLogger.Log.Append("Executing DuckDB raw_sensor copy", LogLevel.Info);
                    using var operationTiming = DuckDbOperationMetrics.Start(DuckDbOperation.RawSensorCopy);
                    try
                    {
                        command.ExecuteNonQuery();
                    }
                    catch
                    {
                        operationTiming.MarkFailed();
                        throw;
                    }
                }
            }

            if (File.Exists(destinationFile))
            {
                File.Delete(destinationFile);
            }

            File.Move(tempDestinationFile, destinationFile);
        }

        private static string DuckDBPath(string path)
        {
            return path.Replace("\\", "/").Replace("'", "''");
        }

        private readonly struct ParsedMergedFile
        {
            internal ParsedMergedFile(string hostname, string eventType, long dataCaptureFileTimeUtc)
            {
                Hostname = hostname;
                EventType = eventType;
                DataCaptureFileTimeUtc = dataCaptureFileTimeUtc;
            }

            internal string Hostname { get; }
            internal string EventType { get; }
            internal long DataCaptureFileTimeUtc { get; }
        }
    }
}
