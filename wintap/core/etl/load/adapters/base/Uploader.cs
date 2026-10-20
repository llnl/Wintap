using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            string relativePath = getParquetRelativePathForFile(localFile).Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
            string objectPrefix = getConfiguredPathPrefix(parameters).Replace('\\', '/').Trim('/');

            if (string.IsNullOrWhiteSpace(objectPrefix))
            {
                return relativePath;
            }

            return objectPrefix + "/" + relativePath.TrimStart('/');
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
