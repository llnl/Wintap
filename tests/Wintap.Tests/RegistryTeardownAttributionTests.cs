using System;
using DuckDB.NET.Data;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class RegistryTeardownAttributionTests : IDisposable
    {
        private readonly DuckDBConnection db = new DuckDBConnection("DataSource=:memory:");
        private readonly ProcessResolver resolver;
        private static readonly DateTime Exit = new DateTime(2026, 10, 13, 22, 19, 0, DateTimeKind.Utc);
        private const string Bam = @"registry\machine\system\controlset001\services\bam\state\usersettings\S-1-5-21-1001";
        public RegistryTeardownAttributionTests()
        {
            db.Open(); ProcessResolver.EnsureEventStoreTables(db);
            resolver = new ProcessResolver(db, 16, registrationLogSink: (_, _) => { });
            Insert("old", Exit.AddSeconds(-1), Exit);
        }
        private void Insert(string hash, DateTime start, DateTime? stop, string name = "conhost.exe")
        {
            using var command = db.CreateCommand();
            command.CommandText = "INSERT INTO process VALUES ($hash, '', 42, 1, $name, '', '', $start, $stop, 0, 'real_time', '', '', '')";
            command.Parameters.Add(new DuckDBParameter("hash", hash));
            command.Parameters.Add(new DuckDBParameter("name", name));
            command.Parameters.Add(new DuckDBParameter("start", start));
            command.Parameters.Add(new DuckDBParameter("stop", stop.HasValue ? stop.Value : DBNull.Value));
            command.ExecuteNonQuery();
        }
        private WintapMessage Message(long ticks) => new WintapMessage(Exit.AddTicks(ticks), 42, WintapMessage.MessageTypeEnum.Registry) {
            ActivityType = WintapMessage.ActivityTypeEnum.Write,
            Registry = new WintapMessage.RegActivityObject { Path = Bam, ValueName = @"\Device\HarddiskVolume1\Windows\System32\conhost.exe" }
        };
        private ProcessRecord Resolve(WintapMessage msg, bool windows = true) =>
            EventOwnerSelection.ResolveOwner(resolver, msg, DateTime.FromFileTimeUtc(msg.EventTime), windows, out _);

        [Theory]
        [InlineData(3546)] [InlineData(3555)] [InlineData(3610)] [InlineData(7069)] [InlineData(10000)]
        public void BamWritesJustAfterExitRecoverIdentityWithoutExtendingLifetime(long ticks)
        {
            var message = Message(ticks);
            message.ReceiveTime = Exit.AddSeconds(2).ToFileTimeUtc();
            var owner = Resolve(message);
            Assert.NotNull(owner); Assert.Equal("old", owner.PidHash); Assert.Equal("conhost.exe", owner.ProcessName);
            Assert.Equal(Exit, owner.ExitTime); Assert.Equal(Exit.AddSeconds(-1), owner.CreateTime);
            Assert.Equal(Exit.AddTicks(ticks).ToFileTimeUtc(), message.EventTime);
            // A recovery must not populate the strict cache with an extended lifetime.
            Assert.Null(resolver.ResolveProcessIdentityAtTime(42, Exit.AddTicks(ticks)));
            Assert.Null(resolver.ResolveProcessAtTime(42, Exit.AddTicks(ticks)));
        }
        [Theory]
        [InlineData(10001)] [InlineData(20000000)]
        public void DoesNotRecoverBeyondOneMillisecond(long ticks) => Assert.Null(Resolve(Message(ticks)));
        [Theory]
        [InlineData("registry\\machine\\software\\example")]
        [InlineData("registry\\machine\\system\\controlset001\\services\\bam\\state\\usersettings\\S-1-5-21-1001\\child")]
        [InlineData("registry\\machine\\system\\controlset001\\services\\bamboo\\state\\usersettings\\S-1-5-21-1001")]
        public void OtherKeysKeepStrictLifetimeMatching(string path)
        {
            var message = Message(5000); message.Registry.Path = path; Assert.Null(Resolve(message));
        }
        [Fact]
        public void OtherActivitiesPlatformsAndStreamsKeepStrictMatching()
        {
            var message = Message(5000); message.ActivityType = WintapMessage.ActivityTypeEnum.Read; Assert.Null(Resolve(message));
            message = Message(5000); Assert.Null(Resolve(message, false));
            message.MessageType = WintapMessage.MessageTypeEnum.File; Assert.Null(Resolve(message));
            message = Message(5000); message.Registry = null; Assert.Null(Resolve(message));
        }
        [Fact]
        public void ExactNewOwnerWinsAndFutureReuseDoesNotStealOldTeardown()
        {
            Insert("new", Exit.AddTicks(8000), null, "new.exe");
            Assert.Equal("old", Resolve(Message(5000)).PidHash);
            Assert.Equal("new", Resolve(Message(9000)).PidHash);
        }
        [Fact]
        public void MostRecentInstanceIsUsedRatherThanAnOlderExit()
        {
            Insert("new", Exit.AddTicks(1000), Exit.AddTicks(2000), "new.exe");
            Assert.Equal("new", Resolve(Message(5000)).PidHash);
        }
        [Fact]
        public void TiedCreationTimesAreAmbiguous()
        {
            Insert("duplicate", Exit.AddSeconds(-1), Exit);
            Assert.Null(Resolve(Message(5000)));
        }
        [Fact]
        public void LateProcessRecordResolvesDeferredEventAtOriginalEventTime()
        {
            var message = Message(20000000);
            message.ActivityType = WintapMessage.ActivityTypeEnum.CreateKey;
            message.Registry.Path = @"registry\machine\software\example";
            long originalTime = message.EventTime, now = 0;
            ProcessRecord emitted = null; int emissions = 0;
            var queue = new AttributionRetryQueue((m, _) => { emitted = Resolve(m); emissions++; },
                clock: () => now, startTimer: false);
            Assert.Null(Resolve(message)); Assert.True(queue.TrySchedule(message, 0));
            // Simulate the other ETW session delivering Start and Stop after Registry.
            Insert("late", Exit.AddSeconds(1), Exit.AddSeconds(3), "rundll32.exe");
            now = 1000; queue.Pump(); queue.Pump();
            Assert.Equal(1, emissions); Assert.Equal("late", emitted.PidHash);
            Assert.Equal(originalTime, message.EventTime); queue.Shutdown();
        }
        public void Dispose() => db.Dispose();
    }
}
