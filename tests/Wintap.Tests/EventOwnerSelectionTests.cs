using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;
using MessageType = gov.llnl.wintap.collect.models.WintapMessage.MessageTypeEnum;

namespace Wintap.Tests
{
    [Trait("Category", "pai-08")]
    public class EventOwnerSelectionTests
    {
        private static readonly DateTime Time = new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc).AddTicks(5678);

        public static IEnumerable<object[]> Routes()
        {
            foreach (MessageType type in Enum.GetValues<MessageType>().Where(t => t != MessageType.Process))
                foreach (bool windows in new[] { true, false })
                    foreach (int outcome in new[] { 0, 1, 2 })
                        yield return new object[] { type, windows, outcome };
        }

        [Theory, MemberData(nameof(Routes))]
        public void ResolvesExactOwnerWithoutMutatingMessage(MessageType type, bool windows, int outcome)
        {
            var message = Message(type);
            // Linux file/network callbacks and SELinux events may carry a complete producer-side identity.
            if (!CanUsePrepopulatedIdentity(type)) { message.PidHash = "prepopulated"; message.ProcessName = "prepopulated"; }
            string before = JsonSerializer.Serialize(message);
            var owner = new ProcessRecord { ProcessId = 42, PidHash = "resolved", ProcessName = "owner", CreateTime = Time.AddSeconds(-1) };
            var resolver = new RecordingResolver
            {
                Current = outcome == 0 ? owner : null,
                Identity = outcome == 1 ? owner : null,
                Durable = outcome == 2 ? null : owner
            };
            ProcessRecord result = EventOwnerSelection.ResolveOwner(resolver, message, Time, windows, out bool? signal);
            Assert.Same(outcome == 2 ? null : owner, result);
            Assert.Equal(type == MessageType.File ? (bool?)(outcome == 0) : null, signal);
            Assert.Equal(outcome == 0 ? new[] { "current" } : new[] { "current", "identity" },
                resolver.Calls.Select(c => c.Method).ToArray());
            Assert.All(resolver.Calls, call => { Assert.Equal(42, call.Pid); Assert.Equal(Time, call.Time); Assert.Equal(DateTimeKind.Utc, call.Time.Kind); });
            Assert.Equal(before, JsonSerializer.Serialize(message));
        }

        public static IEnumerable<object[]> PrepopulatedIdentityTypes()
        {
            foreach (MessageType type in new[] { MessageType.File, MessageType.TcpConnection, MessageType.UdpPacket, MessageType.SELinuxAvc, MessageType.SELinuxTransition, MessageType.SELinuxInteraction })
                foreach (bool windows in new[] { true, false })
                    foreach (string hash in new[] { null, "", " ", "hash" })
                        foreach (string name in new[] { null, "", "\t", "name" })
                            yield return new object[] { type, windows, hash, name };
        }

        [Theory, MemberData(nameof(PrepopulatedIdentityTypes))]
        public void OnlyCompletePrepopulatedIdentityBypassesResolver(MessageType type, bool windows, string hash, string name)
        {
            var message = Message(type);
            message.PidHash = hash;
            message.ProcessName = name;
            string before = JsonSerializer.Serialize(message);
            var resolver = new RecordingResolver();
            var owner = EventOwnerSelection.ResolveOwner(resolver, message, Time, windows, out bool? signal);
            if (!string.IsNullOrWhiteSpace(hash) && !string.IsNullOrWhiteSpace(name))
            {
                Assert.Empty(resolver.Calls);
                Assert.Null(signal);
                Assert.Equal(hash, owner.PidHash);
                Assert.Equal(name, owner.ProcessName);
                Assert.Equal(42, owner.ProcessId);
                Assert.Equal(Time, owner.CreateTime);
                Assert.Null(owner.ExitTime);
            }
            else
            {
                Assert.Null(owner);
                Assert.Equal(type == MessageType.File ? (bool?)false : null, signal);
                Assert.Equal(new[] { "current", "identity" },
                    resolver.Calls.Select(c => c.Method).ToArray());
            }
            Assert.Equal(before, JsonSerializer.Serialize(message));
        }

        [Theory]
        [InlineData(MessageType.File, true, "current", null)]
        [InlineData(MessageType.File, true, "identity", false)]
        [InlineData(MessageType.File, false, "current", null)]
        [InlineData(MessageType.File, false, "identity", false)]
        [InlineData(MessageType.Registry, true, "current", null)]
        [InlineData(MessageType.Registry, true, "identity", null)]
        public void ExceptionsPropagateWithOnlyCompletedFileAttemptsSignaled(
            MessageType type, bool windows, string throwingMethod, bool? expectedSignal)
        {
            var resolver = new RecordingResolver { ThrowOn = throwingMethod };
            var message = Message(type);
            string before = JsonSerializer.Serialize(message);
            bool? signal = null;
            var error = Assert.Throws<InvalidOperationException>(() =>
                EventOwnerSelection.ResolveOwner(resolver, message, Time, windows, out signal));
            Assert.Same(resolver.Error, error);
            Assert.Equal(expectedSignal, signal);
            Assert.Equal(throwingMethod == "identity" ? new[] { "current", "identity" } : new[] { throwingMethod },
                resolver.Calls.Select(c => c.Method).ToArray());
            Assert.All(resolver.Calls, call => { Assert.Equal(42, call.Pid); Assert.Equal(Time, call.Time); });
            Assert.Equal(before, JsonSerializer.Serialize(message));
        }

        private static WintapMessage Message(MessageType type) => new WintapMessage(Time, 42, type)
        {
            PidHash = "", ProcessName = "", EventTime = Time.ToFileTimeUtc()
        };

        private static bool CanUsePrepopulatedIdentity(MessageType type) =>
            type == MessageType.File ||
            type == MessageType.TcpConnection ||
            type == MessageType.UdpPacket ||
            type == MessageType.SELinuxAvc ||
            type == MessageType.SELinuxTransition ||
            type == MessageType.SELinuxInteraction;

        private sealed class RecordingResolver : IProcessResolver
        {
            internal readonly List<(string Method, int Pid, DateTime Time)> Calls = new();
            internal ProcessRecord Current, Identity, Durable;
            internal string ThrowOn;
            internal readonly InvalidOperationException Error = new("lookup failed");
            private ProcessRecord Record(string method, int pid, DateTime time, ProcessRecord result)
            {
                Calls.Add((method, pid, time));
                if (ThrowOn == method) throw Error;
                return result;
            }
            public bool TryResolveCurrentProcessAtTime(int pid, DateTime time, out ProcessRecord process)
            {
                process = Record("current", pid, time, Current);
                return process != null;
            }
            public ProcessRecord ResolveProcessIdentityAtTime(int pid, DateTime time) => Record("identity", pid, time, Identity);
            public ProcessRecord ResolveProcessAtTime(int pid, DateTime time) => Record("durable", pid, time, Durable);
            public ProcessRecord ResolveRegistryTeardownProcess(int pid, DateTime time) => Record("teardown", pid, time, null);
            public void TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out long evictions, out int entries) => throw new NotSupportedException();
            public void RegisterProcess(WintapMessage message) => throw new NotSupportedException();
            public bool ProcessExistsForPid(int pid, long time) => throw new NotSupportedException();
            public bool IsProcessRowOpen(string hash) => throw new NotSupportedException();
            public void UpdateCollectionHeartbeat() => throw new NotSupportedException();
            public bool TryReadCollectionHeartbeat(out DateTime time, out string session) => throw new NotSupportedException();
            public int ReconcileStartupOpenRows(IReadOnlyCollection<string> hashes, DateTime time) => throw new NotSupportedException();
            public bool TryRepairParentLinkage(string hash, int pid, string parentHash) => throw new NotSupportedException();
            public void WriteCollectionGap(DateTime start, DateTime end, string session, string reason) => throw new NotSupportedException();
            public string GetPidHash(int pid, DateTime time) => throw new NotSupportedException();
            public List<ProcessRecord> GetAllProcesses() => throw new NotSupportedException();
            public void ClearDB() => throw new NotSupportedException();
        }
    }
}
