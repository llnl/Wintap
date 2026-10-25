using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class SensorShutdownOrderTests
    {
        [Fact]
        public void DataProducersStopBeforeIdentityWithoutMutatingStartupOrder()
        {
            var startup = new[] { "exec", "clone", "exit", "network", "file", "selinux", "rundown" };
            var identity = new HashSet<string> { "exec", "clone", "exit", "rundown" };
            var stopped = SensorShutdownOrder.DependentsBeforeIdentity(startup, identity.Contains).ToArray();
            Assert.Equal(new[] { "network", "file", "selinux", "exec", "clone", "exit", "rundown" }, stopped);
            Assert.Equal(new[] { "exec", "clone", "exit", "network", "file", "selinux", "rundown" }, startup);
            Assert.Equal(startup.Length, stopped.Distinct().Count());
        }

        [Fact]
        public void FinalDataCallbackStillHasLifecycleEvidence()
        {
            bool identityAlive = true;
            var callbacks = new List<string>();
            foreach (string producer in SensorShutdownOrder.DependentsBeforeIdentity(
                new[] { "identity", "data" }, p => p == "identity"))
            {
                if (producer == "identity") identityAlive = false;
                else Assert.True(identityAlive);
                callbacks.Add(producer);
            }
            Assert.Equal(new[] { "data", "identity" }, callbacks);
        }

        [Fact]
        public void FinalDataCallbackCanRetryUntilLifecycleEvidenceAndFinalDrain()
        {
            bool birthAvailable = false;
            var sent = new List<bool>();
            var message = new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.File);
            var retries = new AttributionRetryQueue((_, _) => sent.Add(birthAvailable), startTimer: false);
            foreach (string producer in SensorShutdownOrder.DependentsBeforeIdentity(
                new[] { "identity", "data" }, p => p == "identity"))
            {
                if (producer == "data") Assert.True(retries.TrySchedule(message, 0));
                else birthAvailable = true; // Last lifecycle callback completes.
            }
            retries.Shutdown();
            Assert.Equal(new[] { true }, sent);
            Assert.False(retries.TrySchedule(message, 0));
        }

        [Fact]
        public void LinuxCallSitesUseOrderedStopsAndLateRetryDrain()
        {
            var repo = new DirectoryInfo(AppContext.BaseDirectory);
            while (repo != null && !File.Exists(Path.Combine(repo.FullName, "Directory.Build.props"))) repo = repo.Parent;
            Assert.NotNull(repo);
            string subscriptions = File.ReadAllText(Path.Combine(repo.FullName, "wintap/core/infrastructure/SubscriptionManager.cs"));
            Assert.Contains("SensorShutdownOrder.DependentsBeforeIdentity", subscriptions);
            foreach (string sensor in new[] { "ExecveSensor", "CloneSensor", "ExitSensor", "ProcessRundownSensor" })
                Assert.Contains("collector is gov.llnl.wintap.platform.linux.collect." + sensor, subscriptions);
            string service = File.ReadAllText(Path.Combine(repo.FullName, "wintap/core/infrastructure/WintapSvcCore.cs"));
            Assert.Contains("#if !LINUX\n                EventChannel.FlushPendingAttributionEvents();", service.Replace("\r\n", "\n"));
            Assert.True(service.LastIndexOf("EventChannel.FlushPendingAttributionEvents();", StringComparison.Ordinal) >
                        service.IndexOf("subscriptionMgr.Stop();", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void OnePhaseAndEmptyListsPreserveOrder(bool identity)
        {
            Assert.Equal(new[] { 1, 2, 3 }, SensorShutdownOrder.DependentsBeforeIdentity(new[] { 1, 2, 3 }, _ => identity));
            Assert.Empty(SensorShutdownOrder.DependentsBeforeIdentity(Array.Empty<int>(), _ => identity));
        }
    }
}
