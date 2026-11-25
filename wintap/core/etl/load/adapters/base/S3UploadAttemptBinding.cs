using System;
using System.IO;
using System.Text.Json;

namespace gov.llnl.wintap.core.etl.load.adapters.baseclass
{
    internal enum S3UploadHeadStatus
    {
        Exists,
        NotFound,
        Unknown,
        Mismatch
    }

    internal enum S3UploadBindingDisposition
    {
        AlreadyUploaded,
        RebindCurrentKey,
        RetryExactKey,
        Reject
    }

    internal static class S3UploadAttemptPolicy
    {
        internal static S3UploadBindingDisposition Decide(S3UploadHeadStatus status)
        {
            switch (status)
            {
                case S3UploadHeadStatus.Exists:
                    return S3UploadBindingDisposition.AlreadyUploaded;
                case S3UploadHeadStatus.NotFound:
                    return S3UploadBindingDisposition.RebindCurrentKey;
                case S3UploadHeadStatus.Unknown:
                    return S3UploadBindingDisposition.RetryExactKey;
                default:
                    return S3UploadBindingDisposition.Reject;
            }
        }
    }

    /// <summary>
    /// Durable publication state for an S3 upload whose result may be unknown.
    /// The sidecar is intentionally local and is ignored by the parquet scanner.
    /// </summary>
    internal sealed class S3UploadAttemptBinding
    {
        internal const string SidecarSuffix = ".s3upload.json";

        public string ObjectKey { get; set; }
        public string UploadIdentity { get; set; }
        public long FileLength { get; set; }
        public long LastWriteTimeUtcTicks { get; set; }
        public long AttemptedAtUtcTicks { get; set; }

        internal static string GetSidecarPath(string localFile)
        {
            return Path.GetFullPath(localFile) + SidecarSuffix;
        }

        internal static S3UploadAttemptBinding LoadIfPresent(string localFile)
        {
            string sidecarPath = GetSidecarPath(localFile);
            if (!File.Exists(sidecarPath))
            {
                return null;
            }

            S3UploadAttemptBinding binding;
            try
            {
                binding = JsonSerializer.Deserialize<S3UploadAttemptBinding>(File.ReadAllText(sidecarPath));
            }
            catch (Exception ex) when (ex is IOException || ex is JsonException)
            {
                throw new InvalidDataException("Could not read S3 upload sidecar: " + sidecarPath, ex);
            }

            if (binding == null || string.IsNullOrWhiteSpace(binding.ObjectKey) ||
                string.IsNullOrWhiteSpace(binding.UploadIdentity) ||
                binding.FileLength < 0 || binding.LastWriteTimeUtcTicks <= 0 ||
                binding.AttemptedAtUtcTicks <= 0)
            {
                throw new InvalidDataException("S3 upload sidecar is incomplete: " + sidecarPath);
            }

            FileInfo file = new FileInfo(localFile);
            if (!file.Exists)
            {
                throw new FileNotFoundException("S3 upload sidecar has no source file", localFile);
            }

            if (file.Length != binding.FileLength || file.LastWriteTimeUtc.Ticks != binding.LastWriteTimeUtcTicks)
            {
                throw new InvalidDataException(
                    "S3 upload sidecar does not match the current source file: " + sidecarPath);
            }

            return binding;
        }

        internal static S3UploadAttemptBinding CreateAtomically(
            string localFile,
            string objectKey,
            DateTime attemptedAtUtc)
        {
            if (string.IsNullOrWhiteSpace(objectKey))
            {
                throw new ArgumentException("An S3 object key is required.", nameof(objectKey));
            }

            S3UploadAttemptBinding existing = LoadIfPresent(localFile);
            if (existing != null)
            {
                return existing;
            }

            FileInfo file = new FileInfo(localFile);
            if (!file.Exists)
            {
                throw new FileNotFoundException("Local file does not exist", localFile);
            }

            DateTime utc = attemptedAtUtc.Kind == DateTimeKind.Local
                ? attemptedAtUtc.ToUniversalTime()
                : DateTime.SpecifyKind(attemptedAtUtc, DateTimeKind.Utc);
            S3UploadAttemptBinding binding = new S3UploadAttemptBinding
            {
                ObjectKey = objectKey,
                UploadIdentity = Guid.NewGuid().ToString("N"),
                FileLength = file.Length,
                LastWriteTimeUtcTicks = file.LastWriteTimeUtc.Ticks,
                AttemptedAtUtcTicks = utc.Ticks
            };

            string sidecarPath = GetSidecarPath(localFile);
            string temporaryPath = sidecarPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporaryPath, JsonSerializer.Serialize(binding));
                try
                {
                    File.Move(temporaryPath, sidecarPath);
                    return binding;
                }
                catch (IOException)
                {
                    S3UploadAttemptBinding winner = LoadIfPresent(localFile);
                    if (winner != null)
                    {
                        return winner;
                    }

                    throw;
                }
            }
            finally
            {
                try
                {
                    if (File.Exists(temporaryPath))
                    {
                        File.Delete(temporaryPath);
                    }
                }
                catch
                {
                    // Temporary artifacts are never treated as parquet input.
                }
            }
        }

        internal bool Matches(FileInfo file, long remoteLength, string remoteIdentity)
        {
            return file != null && file.Length == FileLength &&
                remoteLength == FileLength &&
                string.Equals(remoteIdentity, UploadIdentity, StringComparison.Ordinal);
        }

        internal static bool DeleteIfPresent(string localFile)
        {
            string sidecarPath = GetSidecarPath(localFile);
            try
            {
                if (File.Exists(sidecarPath))
                {
                    File.Delete(sidecarPath);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
