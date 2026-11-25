using System;
using System.IO;
using gov.llnl.wintap.core.etl.load.adapters.baseclass;
using Xunit;

namespace Wintap.Tests
{
    public sealed class S3UploadAttemptBindingTests
    {
        [Fact]
        [Trait("Category", "s3u-01")]
        public void RewriteS3UploadPartitionUsesUtcUploadTimeAndPreservesPayloadPath()
        {
            string result = Uploader.RewriteS3UploadPartition(
                "raw_sensor/raw_process/dayPK=20260131/hourPK=23/protoPK=tcp/host+process+timestamp.parquet",
                new DateTime(2026, 2, 1, 0, 4, 0, DateTimeKind.Utc));

            Assert.Equal(
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/protoPK=tcp/host+process+timestamp.parquet",
                result);
        }

        [Fact]
        [Trait("Category", "s3u-01")]
        public void RewriteS3UploadPartitionRejectsNonCanonicalPath()
        {
            Assert.Throws<FormatException>(() => Uploader.RewriteS3UploadPartition(
                "raw_sensor/raw_process/host+process+timestamp.parquet",
                DateTime.UtcNow));
        }

        [Fact]
        [Trait("Category", "s3u-02")]
        public void BindingSurvivesReloadAndRecordsTheExactSourceIdentity()
        {
            using TemporaryFile file = TemporaryFile.Create("payload");
            DateTime attemptedAtUtc = new DateTime(2026, 2, 1, 0, 4, 0, DateTimeKind.Utc);

            S3UploadAttemptBinding created = S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/file.parquet",
                attemptedAtUtc);
            S3UploadAttemptBinding loaded = S3UploadAttemptBinding.LoadIfPresent(file.Path);

            Assert.Equal(created.ObjectKey, loaded.ObjectKey);
            Assert.Equal(created.UploadIdentity, loaded.UploadIdentity);
            Assert.Equal(new FileInfo(file.Path).Length, loaded.FileLength);
            Assert.True(File.Exists(S3UploadAttemptBinding.GetSidecarPath(file.Path)));
        }

        [Fact]
        [Trait("Category", "s3u-02")]
        public void BindingRejectsAChangedSourceFile()
        {
            using TemporaryFile file = TemporaryFile.Create("payload");
            S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/file.parquet",
                DateTime.UtcNow);

            File.AppendAllText(file.Path, "changed");

            Assert.Throws<InvalidDataException>(() => S3UploadAttemptBinding.LoadIfPresent(file.Path));
        }

        [Fact]
        [Trait("Category", "s3u-02")]
        public void BindingRecognizesOnlyTheMatchingRemoteObject()
        {
            using TemporaryFile file = TemporaryFile.Create("payload");
            S3UploadAttemptBinding binding = S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/file.parquet",
                DateTime.UtcNow);

            Assert.True(binding.Matches(
                new FileInfo(file.Path),
                file.Length,
                binding.UploadIdentity));
            Assert.False(binding.Matches(
                new FileInfo(file.Path),
                file.Length + 1,
                binding.UploadIdentity));
            Assert.False(binding.Matches(
                new FileInfo(file.Path),
                file.Length,
                "different-upload"));
        }

        [Fact]
        [Trait("Category", "s3u-03")]
        public void HeadOutcomesNeverCreateASecondKeyAfterAnInconclusiveCheck()
        {
            Assert.Equal(
                S3UploadBindingDisposition.AlreadyUploaded,
                S3UploadAttemptPolicy.Decide(S3UploadHeadStatus.Exists));
            Assert.Equal(
                S3UploadBindingDisposition.RebindCurrentKey,
                S3UploadAttemptPolicy.Decide(S3UploadHeadStatus.NotFound));
            Assert.Equal(
                S3UploadBindingDisposition.RetryExactKey,
                S3UploadAttemptPolicy.Decide(S3UploadHeadStatus.Unknown));
            Assert.Equal(
                S3UploadBindingDisposition.Reject,
                S3UploadAttemptPolicy.Decide(S3UploadHeadStatus.Mismatch));
        }

        [Fact]
        [Trait("Category", "s3u-03")]
        public void AConfirmedMissingAttemptCanBeReboundToANewCurrentKey()
        {
            using TemporaryFile file = TemporaryFile.Create("payload");
            S3UploadAttemptBinding first = S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/file.parquet",
                DateTime.UtcNow);

            Assert.True(S3UploadAttemptBinding.DeleteIfPresent(file.Path));
            S3UploadAttemptBinding rebound = S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260202/hourPK=01/file.parquet",
                DateTime.UtcNow);

            Assert.NotEqual(first.ObjectKey, rebound.ObjectKey);
            Assert.NotEqual(first.UploadIdentity, rebound.UploadIdentity);
        }

        [Fact]
        [Trait("Category", "s3u-02")]
        public void DeleteIfPresentRemovesTheBindingWithoutRemovingTheSource()
        {
            using TemporaryFile file = TemporaryFile.Create("payload");
            S3UploadAttemptBinding.CreateAtomically(
                file.Path,
                "raw_sensor/raw_process/dayPK=20260201/hourPK=00/file.parquet",
                DateTime.UtcNow);

            Assert.True(S3UploadAttemptBinding.DeleteIfPresent(file.Path));
            Assert.True(File.Exists(file.Path));
            Assert.False(File.Exists(S3UploadAttemptBinding.GetSidecarPath(file.Path)));
        }

        private sealed class TemporaryFile : IDisposable
        {
            private TemporaryFile(string path)
            {
                Path = path;
            }

            internal string Path { get; }

            internal long Length => new FileInfo(Path).Length;

            internal static TemporaryFile Create(string contents)
            {
                string path = System.IO.Path.Combine(
                    System.IO.Path.GetTempPath(),
                    "wintap-s3-upload-" + Guid.NewGuid().ToString("N") + ".parquet");
                File.WriteAllText(path, contents);
                return new TemporaryFile(path);
            }

            public void Dispose()
            {
                try
                {
                    File.Delete(Path);
                    File.Delete(S3UploadAttemptBinding.GetSidecarPath(Path));
                }
                catch
                {
                    // Best-effort test cleanup.
                }
            }
        }
    }
}
