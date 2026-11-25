using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.etl.load.adapters.baseclass
{
    internal class Uploader
    {
        protected int counter;
        protected Stopwatch watch;

        public string Name { get; set; }

        public Uploader()
        {
            counter = 0;
            watch = new Stopwatch();
        }

        protected void startSessionStats()
        {
            watch.Start();
        }

        protected void updateSessionStats()
        {
            counter++;
        }

        protected void stopSessionStats()
        {
            this.watch.Stop();
            WintapLogger.Log.Append("Uploader: " + this.Name + " uploaded " + counter + " files in " + watch.Elapsed.TotalSeconds + " seconds", LogLevel.Info);
            this.watch.Reset();
            this.counter = 0;
        }

        /// <summary>
        /// Converts a local parquet path to an S3 object key while preserving the canonical
        /// raw_sensor directory layout. For example:
        ///   {parquetRoot}/raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet
        /// becomes:
        ///   raw_sensor/raw_process/dayPK=20260529/hourPK=13/file.parquet
        /// Optional config properties KeyPrefix, Path, or ObjectPrefix are prepended when set.
        /// </summary>
        protected string getS3ObjectNameForFile(string localFile, Dictionary<string, string> parameters)
        {
            return getS3ObjectNameForFile(localFile, DateTime.UtcNow, parameters);
        }

        /// <summary>
        /// Converts a local parquet path to an S3 key using the supplied UTC upload
        /// time for the canonical day/hour partition. The caller should capture the
        /// time once per publication attempt and reuse the resulting key for retries.
        /// </summary>
        protected string getS3ObjectNameForFile(string localFile, DateTime uploadTimeUtc, Dictionary<string, string> parameters)
        {
            string relativePath = RewriteS3UploadPartition(
                getParquetRelativePathForFile(localFile),
                uploadTimeUtc);
            string objectPrefix = getConfiguredPathPrefix(parameters).Replace('\\', '/').Trim('/');

            if (string.IsNullOrWhiteSpace(objectPrefix))
            {
                return relativePath;
            }

            return objectPrefix + "/" + relativePath.TrimStart('/');
        }

        /// <summary>
        /// Rewrites only the canonical raw_sensor day/hour path segments. The event
        /// type, protocol partition, filename, and all other path segments remain
        /// unchanged.
        /// </summary>
        internal static string RewriteS3UploadPartition(string relativePath, DateTime uploadTimeUtc)
        {
            if (string.IsNullOrWhiteSpace(relativePath))
            {
                throw new ArgumentException("A relative parquet path is required.", nameof(relativePath));
            }

            DateTime utc = uploadTimeUtc.Kind == DateTimeKind.Local
                ? uploadTimeUtc.ToUniversalTime()
                : DateTime.SpecifyKind(uploadTimeUtc, DateTimeKind.Utc);
            string normalizedPath = relativePath.Replace('\\', '/');
            string[] segments = normalizedPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            int rawSensorIndex = Array.FindIndex(segments, segment =>
                segment.Equals("raw_sensor", StringComparison.OrdinalIgnoreCase));
            int dayIndex = Array.FindIndex(segments, segment =>
                segment.StartsWith("dayPK=", StringComparison.OrdinalIgnoreCase));
            int hourIndex = Array.FindIndex(segments, segment =>
                segment.StartsWith("hourPK=", StringComparison.OrdinalIgnoreCase));

            if (rawSensorIndex < 0 || dayIndex != rawSensorIndex + 2 || hourIndex != dayIndex + 1)
            {
                throw new FormatException(
                    "The parquet path does not contain a canonical raw_sensor/dayPK/hourPK partition: " + relativePath);
            }

            segments[dayIndex] = "dayPK=" + utc.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
            segments[hourIndex] = "hourPK=" + utc.ToString("HH", CultureInfo.InvariantCulture);
            return string.Join('/', segments);
        }

        /// <summary>
        /// Converts a local parquet path to a relative destination path for file-share uploaders,
        /// preserving raw_sensor as the top-level folder and applying optional KeyPrefix/Path/ObjectPrefix.
        /// </summary>
        protected string getFileShareRelativePathForFile(string localFile, Dictionary<string, string> parameters)
        {
            string relativePath = getParquetRelativePathForFile(localFile);
            string configuredPrefix = getConfiguredPathPrefix(parameters);

            if (string.IsNullOrWhiteSpace(configuredPrefix))
            {
                return relativePath;
            }

            configuredPrefix = configuredPrefix.Trim(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, '/', '\\');
            return Path.Combine(configuredPrefix, relativePath);
        }

        protected string getParameter(Dictionary<string, string> parameters, string key, string defaultValue = "")
        {
            if (parameters != null && parameters.TryGetValue(key, out string value) && value != null)
            {
                return value;
            }

            return defaultValue;
        }

        private string getParquetRelativePathForFile(string localFile)
        {
            return GetParquetRelativePathForFile(localFile, Paths.ParquetDataPath);
        }

        internal static string GetParquetRelativePathForFile(string localFile, string parquetDataRoot)
        {
            string fullPath = Path.GetFullPath(localFile);
            string parquetRoot = Path.GetFullPath(parquetDataRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

            if (fullPath.StartsWith(parquetRoot, StringComparison.OrdinalIgnoreCase))
            {
                return fullPath.Substring(parquetRoot.Length);
            }

            string rawSensorMarker = Path.DirectorySeparatorChar + "raw_sensor" + Path.DirectorySeparatorChar;
            int rawSensorIndex = fullPath.IndexOf(rawSensorMarker, StringComparison.OrdinalIgnoreCase);
            if (rawSensorIndex >= 0)
            {
                return fullPath.Substring(rawSensorIndex + 1);
            }

            WintapLogger.Log.Append($"Could not resolve parquet-relative path for {localFile}; using file name only", LogLevel.Warn);
            return Path.GetFileName(localFile);
        }

        private string getConfiguredPathPrefix(Dictionary<string, string> parameters)
        {
            string prefix = getParameter(parameters, "KeyPrefix");
            if (string.IsNullOrWhiteSpace(prefix))
            {
                prefix = getParameter(parameters, "Path");
            }
            if (string.IsNullOrWhiteSpace(prefix))
            {
                prefix = getParameter(parameters, "ObjectPrefix");
            }

            return prefix ?? string.Empty;
        }
    }
}
