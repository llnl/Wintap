using System;
using System.Collections.Generic;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using Xunit;

namespace Wintap.Tests
{
    [Trait("Category", "windows-shell")]
    public class WindowsShellSensorTests
    {
        private static readonly DateTime Start = new DateTime(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc).AddTicks(1234567);
        private static readonly DateTime EventTime = Start.AddSeconds(10);
        private const int ClientPid = 42;
        private const string Text = "echo café & dir \".\\Sample Folder\"\r\n";

        private static Dictionary<string, object> Fields() => new Dictionary<string, object>
        {
            ["AttachedProcessId"] = ClientPid,
            ["AttachedProcessCreationTime"] = Start.ToFileTimeUtc(),
            ["ReadBuffer"] = Text,
            ["ReadBufferLength"] = Text.Length
        };

        private static WindowsShellClientIdentity Verified(int pid, long start) =>
            new WindowsShellClientIdentity(pid == ClientPid, 3, "cmd.exe", start);

        private static bool Decode(Dictionary<string, object> fields, out WintapMessage message, out string status) =>
            WindowsShellSensor.TryCreateMessage(fields, EventTime, Verified, out message, out status);

        [Fact]
        public void UsesAttachedClientPidAndProviderTimeRatherThanHostProcess()
        {
            var fields = Fields();
            fields["ProcessID"] = 987;
            fields["PID"] = 988;
            int inspectedPid = 0;
            long inspectedStart = 0;
            Assert.True(WindowsShellSensor.TryCreateMessage(fields, EventTime, (pid, start) =>
            {
                inspectedPid = pid;
                inspectedStart = start;
                return Verified(pid, start);
            }, out WintapMessage message, out string status));
            Assert.Equal("ok", status);
            Assert.Equal(ClientPid, inspectedPid);
            Assert.Equal(Start.ToFileTimeUtc(), inspectedStart);
            Assert.Equal(ClientPid, message.PID);
            Assert.Equal(EventTime.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(WintapMessage.MessageTypeEnum.WindowsShell, message.MessageType);
            Assert.Equal(WintapMessage.ActivityTypeEnum.EventWritten, message.ActivityType);
            Assert.Equal(Text, message.WindowsShell.CommandText);
            Assert.Equal(3, message.WindowsShell.SessionId);
            Assert.True(ProcessAttribution.TryApply(message, new ProcessRecord
            {
                ProcessId = ClientPid, CreateTime = Start, PidHash = "canonical", ProcessName = "cmd.exe"
            }, requireProcessStart: true));
        }

        [Fact]
        public void HostPidCannotReplaceMissingAttachedClientPid()
        {
            var fields = Fields();
            fields.Remove("AttachedProcessId");
            fields["ProcessID"] = ClientPid;
            Assert.False(Decode(fields, out WintapMessage message, out _));
            Assert.Null(message);
        }

        [Theory]
        [InlineData("zero")]
        [InlineData("negative")]
        [InlineData("string")]
        [InlineData("floating")]
        [InlineData("bool")]
        public void InvalidAttachedPidNeverFallsBackToHostPid(string variant)
        {
            var fields = Fields();
            fields["AttachedProcessId"] = variant switch
            {
                "zero" => (object)0,
                "negative" => -1,
                "string" => ClientPid.ToString(),
                "floating" => (double)ClientPid,
                _ => true
            };
            fields["ProcessID"] = ClientPid;
            Assert.False(Decode(fields, out WintapMessage message, out string status));
            Assert.Null(message);
            Assert.Equal("invalid_payload", status);
        }

        [Fact]
        public void Utf16SurrogatePairsArePreservedWithoutScalarLengthGuessing()
        {
            var fields = Fields();
            fields["ReadBuffer"] = "echo 😀\r\n";
            fields["ReadBufferLength"] = ((string)fields["ReadBuffer"]).Length;
            Assert.True(Decode(fields, out WintapMessage message, out _));
            Assert.Equal(fields["ReadBuffer"], message.WindowsShell.CommandText);
        }

        [Theory]
        [InlineData("datetime")]
        [InlineData("offset")]
        [InlineData("long")]
        [InlineData("ulong")]
        public void SupportedCreationVariantsPreserveExactFiletime(string variant)
        {
            var fields = Fields();
            fields["AttachedProcessCreationTime"] = variant switch
            {
                "datetime" => (object)Start,
                "offset" => new DateTimeOffset(Start).ToOffset(TimeSpan.FromHours(2)),
                "ulong" => (ulong)Start.ToFileTimeUtc(),
                _ => Start.ToFileTimeUtc()
            };
            Assert.True(Decode(fields, out WintapMessage message, out _));
            Assert.True(ProcessAttribution.TryApply(message, new ProcessRecord
            {
                ProcessId = ClientPid, CreateTime = Start, PidHash = "canonical", ProcessName = "cmd.exe"
            }, requireProcessStart: true));
        }

        [Theory]
        [InlineData("missing")]
        [InlineData("null")]
        [InlineData("zero")]
        [InlineData("negative")]
        [InlineData("overflow")]
        [InlineData("string")]
        [InlineData("floating")]
        public void UnsupportedCreationNeverGuessesAProcessLifetime(string variant)
        {
            var fields = Fields();
            if (variant == "missing") fields.Remove("AttachedProcessCreationTime");
            else fields["AttachedProcessCreationTime"] = variant switch
            {
                "null" => null,
                "zero" => (object)0L,
                "negative" => -1L,
                "overflow" => ulong.MaxValue,
                "string" => Start.ToFileTimeUtc().ToString(),
                _ => (double)Start.ToFileTimeUtc()
            };
            Assert.False(Decode(fields, out WintapMessage message, out string status));
            Assert.Null(message);
            Assert.Equal("creation_time_unavailable", status);
        }

        [Fact]
        public void OptionalLengthAbsenceDoesNotRewriteUnicodeOrCompoundText()
        {
            var fields = Fields();
            fields.Remove("ReadBufferLength");
            Assert.True(Decode(fields, out WintapMessage message, out _));
            Assert.Equal(Text, message.WindowsShell.CommandText);
        }

        [Theory]
        [InlineData("missing-text")]
        [InlineData("null-text")]
        [InlineData("nonstring-text")]
        [InlineData("empty-text")]
        [InlineData("null-length")]
        [InlineData("short-length")]
        [InlineData("long-length")]
        [InlineData("negative-length")]
        [InlineData("text-length")]
        [InlineData("floating-length")]
        [InlineData("nul-text")]
        public void InvalidTextOrLengthIsSuppressedWithoutPartialCommands(string variant)
        {
            var fields = Fields();
            switch (variant)
            {
                case "missing-text": fields.Remove("ReadBuffer"); break;
                case "null-text": fields["ReadBuffer"] = null; break;
                case "nonstring-text": fields["ReadBuffer"] = new char[] {'d','i','r'}; break;
                case "empty-text": fields["ReadBuffer"] = ""; fields["ReadBufferLength"] = 0; break;
                case "null-length": fields["ReadBufferLength"] = null; break;
                case "short-length": fields["ReadBufferLength"] = Text.Length - 1; break;
                case "long-length": fields["ReadBufferLength"] = Text.Length + 1; break;
                case "negative-length": fields["ReadBufferLength"] = -1; break;
                case "text-length": fields["ReadBufferLength"] = Text.Length.ToString(); break;
                case "floating-length": fields["ReadBufferLength"] = (double)Text.Length; break;
                case "nul-text": fields["ReadBuffer"] = "echo safe\0hidden"; fields["ReadBufferLength"] = 16; break;
            }
            Assert.False(Decode(fields, out WintapMessage message, out string status));
            Assert.Null(message);
            Assert.Equal("invalid_payload", status);
        }

        [Fact]
        public void PayloadLimitsRejectBeforeInspectingProcessAndKeepDiagnosticsGeneric()
        {
            var fields = Fields();
            fields["ReadBuffer"] = new string('x', 65537);
            fields["ReadBufferLength"] = 65537;
            bool inspected = false;
            Assert.False(WindowsShellSensor.TryCreateMessage(fields, EventTime, (pid, start) =>
            {
                inspected = true;
                return Verified(pid, start);
            }, out WintapMessage message, out string status));
            Assert.False(inspected);
            Assert.Null(message);
            Assert.Equal("invalid_payload", status);
            fields = Fields();
            for (int index = 0; index < 65; index++) fields["Extra" + index] = "sample";
            Assert.False(Decode(fields, out _, out status));
            Assert.Equal("invalid_payload", status);
        }

        [Theory]
        [InlineData("unverified")]
        [InlineData("powershell")]
        [InlineData("other-program")]
        [InlineData("pid-reuse")]
        public void OnlyVerifiedCmdLifetimeIsEmitted(string variant)
        {
            var fields = Fields();
            Assert.False(WindowsShellSensor.TryCreateMessage(fields, EventTime, (pid, start) =>
                new WindowsShellClientIdentity(variant != "unverified", 3,
                    variant == "powershell" ? "powershell.exe" : variant == "other-program" ? "sample.exe" : "cmd.exe",
                    variant == "pid-reuse" ? start + 1 : start), out WintapMessage message, out string status));
            Assert.Null(message);
            Assert.Equal(variant switch
            {
                "unverified" => "client_unverified",
                "pid-reuse" => "creation_time_mismatch",
                _ => "not_cmd"
            }, status);
        }

        [Fact]
        public void RepeatedIdenticalSubmissionsRemainSeparateEvents()
        {
            var fields = Fields();
            Assert.True(Decode(fields, out WintapMessage first, out _));
            Assert.True(Decode(fields, out WintapMessage second, out _));
            Assert.NotSame(first, second);
            Assert.Equal(first.WindowsShell.CommandText, second.WindowsShell.CommandText);
        }

        [Fact]
        public void ProviderTimestampBeforeProcessCreationIsSuppressed()
        {
            Assert.False(WindowsShellSensor.TryCreateMessage(Fields(), Start.AddTicks(-1), Verified,
                out WintapMessage message, out string status));
            Assert.Null(message);
            Assert.Equal("invalid_timestamp", status);
        }

        [Fact]
        public void InvalidPayloadCannotEchoCommandContentInStatus()
        {
            var fields = Fields();
            fields["ReadBuffer"] = "echo sample-private-marker";
            fields["ReadBufferLength"] = -1;
            Assert.False(Decode(fields, out _, out string status));
            Assert.Equal("invalid_payload", status);
            Assert.DoesNotContain("sample-private-marker", status);
        }

        [Fact]
        public void SensorRejectsOtherProviderAndUnrelatedEventsBeforeClientInspection()
        {
            int inspected = 0, emitted = 0;
            var sensor = new WindowsShellSensor(_ => emitted++, (pid, start) =>
            {
                inspected++;
                return Verified(pid, start);
            });
            try
            {
                Assert.False(sensor.HandleInputEvent(Guid.Empty, "CookedRead", "CookedRead", EventTime, Fields()));
                Assert.False(sensor.HandleInputEvent(WindowsShellSensor.Provider, "Unrelated", "Unrelated", EventTime, Fields()));
                Assert.Equal(0, inspected);
                Assert.Equal(0, emitted);
            }
            finally { sensor.Stop(); }
        }

        [Theory]
        [InlineData("CookedRead", "")]
        [InlineData("CookedRead/Start", "")]
        [InlineData("", "CookedRead")]
        public void SensorRecognizesProviderInputEventNamesAndPreservesRepeatedSubmissions(string eventName, string taskName)
        {
            var messages = new List<WintapMessage>();
            var sensor = new WindowsShellSensor(messages.Add, Verified);
            try
            {
                Assert.True(sensor.HandleInputEvent(WindowsShellSensor.Provider, eventName, taskName, EventTime, Fields()));
                Assert.True(sensor.HandleInputEvent(WindowsShellSensor.Provider, eventName, taskName, EventTime.AddMilliseconds(1), Fields()));
                Assert.Equal(2, messages.Count);
                Assert.Equal(Text, messages[0].WindowsShell.CommandText);
                Assert.Equal(Text, messages[1].WindowsShell.CommandText);
                Assert.Equal(EventTime.ToFileTimeUtc(), messages[0].EventTime);
                Assert.Equal(EventTime.AddMilliseconds(1).ToFileTimeUtc(), messages[1].EventTime);
                Assert.Equal(2L, sensor.Counter);
            }
            finally { sensor.Stop(); }
        }

        [Fact]
        public void SensorIsIndependentAndStopBeforeStartIsIdempotent()
        {
            var sensor = new WindowsShellSensor(_ => { }, Verified);
            Assert.Equal(gov.llnl.wintap.platform.windows.collect.shared.BaseWindowsSensor.CollectorTypeEnum.General, sensor.CollectorType);
            sensor.Stop();
            sensor.Stop();
        }
    }
}

