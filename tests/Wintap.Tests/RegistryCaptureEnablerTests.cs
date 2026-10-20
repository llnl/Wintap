using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;

namespace Wintap.Tests
{
    public sealed class RegistryCaptureEnablerTests
    {
        private static readonly Guid ProviderId = new Guid("70EB4F03-C1DE-4F73-A051-33D13D5413BD");
        private const ulong TestHandle = 0x1234;
        private const ulong TestMask = 0x5300;
        [Fact, Trait("Category", "wrc-04")]
        public void TraceEventReflectionContractMatchesPinnedVersion()
        {
            FieldInfo field = typeof(TraceEventSession).GetField(
                "m_SessionHandle",
                BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.True(field != null, "TraceEvent 3.1.23 version pin moved: m_SessionHandle is missing.");
            MethodInfo method = field.FieldType.GetMethod(
                "DangerousGetHandle",
                BindingFlags.Instance | BindingFlags.Public,
                null,
                Type.EmptyTypes,
                null);
            Assert.True(method != null, "TraceEvent 3.1.23 version pin moved: DangerousGetHandle() is missing.");
        }

        [Fact, Trait("Category", "wrc-04")]
        public void AcquireHandleRejectsNullFieldValue()
        {
            InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
                () => RegistryCaptureEnabler.AcquireHandleFromFieldValue(null));

            Assert.Contains("TraceEvent", ex.Message);
            Assert.Contains("3.1.23", ex.Message);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void AcquireHandleRejectsValueWithoutDangerousGetHandle()
        {
            InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
                () => RegistryCaptureEnabler.AcquireHandleFromFieldValue(new object()));

            Assert.Contains("TraceEvent", ex.Message);
            Assert.Contains("3.1.23", ex.Message);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void AcquireHandleUsesDuckTypedDangerousGetHandle()
        {
            Assert.Equal(TestHandle, RegistryCaptureEnabler.AcquireHandleFromFieldValue(new FakeSessionHandle()));
        }

        [Fact, Trait("Category", "wrc-04")]
        public void EnableCaptureUsesDisableThenEnableWithExpectedArguments()
        {
            var calls = new List<NativeCall>();
            using var enabler = NewEnabler(RecordCalls(calls));

            enabler.EnableCapture();

            AssertCallSequence(calls);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void EnableCaptureMarshalsExactFourByteCaptureFilter()
        {
            EVENT_FILTER_DESCRIPTOR capturedFilter = default;
            int capturedPayload = 0;
            RegistryCaptureEnabler.NativeEnableTraceEx2 native = (
                ulong handle,
                in Guid provider,
                uint controlCode,
                byte level,
                ulong anyKeyword,
                ulong allKeyword,
                int timeout,
                in ENABLE_TRACE_PARAMETERS parameters) =>
            {
                if (controlCode == 1)
                {
                    capturedFilter = Marshal.PtrToStructure<EVENT_FILTER_DESCRIPTOR>(parameters.EnableFilterDesc);
                    capturedPayload = Marshal.ReadInt32(capturedFilter.Ptr);
                }

                return 0;
            };
            using var enabler = NewEnabler(native);

            enabler.EnableCapture();

            Assert.Equal(4, capturedFilter.Size);
            Assert.Equal(0x1, capturedFilter.Type);
            Assert.Equal(unchecked((int)0xFFFFFFFF), capturedPayload);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void EnableFailureThrowsAndDisableFailureIsTolerated()
        {
            RegistryCaptureEnabler.NativeEnableTraceEx2 enableFails = (
                ulong handle,
                in Guid provider,
                uint controlCode,
                byte level,
                ulong anyKeyword,
                ulong allKeyword,
                int timeout,
                in ENABLE_TRACE_PARAMETERS parameters) => controlCode == 1 ? 5 : 0;
            using var failingEnabler = NewEnabler(enableFails);

            InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => failingEnabler.EnableCapture());
            Assert.Contains("5", ex.Message);

            RegistryCaptureEnabler.NativeEnableTraceEx2 disableFails = (
                ulong handle,
                in Guid provider,
                uint controlCode,
                byte level,
                ulong anyKeyword,
                ulong allKeyword,
                int timeout,
                in ENABLE_TRACE_PARAMETERS parameters) => controlCode == 0 ? 87 : 0;
            using var tolerantEnabler = NewEnabler(disableFails);
            tolerantEnabler.EnableCapture();
        }

        [Fact, Trait("Category", "wrc-04")]
        public void ReassertCaptureRefreshesFilterWithoutDisablingAndIncrementsCount()
        {
            var calls = new List<NativeCall>();
            using var enabler = NewEnabler(RecordCalls(calls));
            enabler.EnableCapture();

            enabler.ReassertCapture();

            Assert.Equal(3, calls.Count);
            AssertCallSequence(calls.GetRange(0, 2));
            // The refresh carries the same enable arguments as startup, without a disable.
            AssertCallSequence(new[] { calls[0], calls[2] });
            Assert.Equal(1, enabler.ReassertCount);
        }

        [Fact]
        public void PeriodicRefreshNeverDisablesHealthyCapture()
        {
            var calls = new List<NativeCall>();
            using var enabler = NewEnabler(RecordCalls(calls));
            for (int i = 0; i < 10; i++) enabler.OnReassertTick();
            Assert.Equal(10, calls.Count);
            Assert.All(calls, call => Assert.Equal(1u, call.ControlCode));
            Assert.Equal(10, enabler.ReassertCount);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void ReassertTickSurvivesFailureAndRetriesSuccessfully()
        {
            bool shouldThrow = true;
            RegistryCaptureEnabler.NativeEnableTraceEx2 native = (
                ulong handle,
                in Guid provider,
                uint controlCode,
                byte level,
                ulong anyKeyword,
                ulong allKeyword,
                int timeout,
                in ENABLE_TRACE_PARAMETERS parameters) =>
            {
                if (shouldThrow)
                {
                    throw new InvalidOperationException("transient native failure");
                }

                return 0;
            };
            using var enabler = NewEnabler(native);

            Exception firstTick = Record.Exception(() => enabler.OnReassertTick());
            shouldThrow = false;
            enabler.OnReassertTick();

            Assert.Null(firstTick);
            Assert.Equal(1, enabler.ReassertCount);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void CaptureLossNotificationImmediatelyReasserts()
        {
            var calls = new List<NativeCall>();
            using var enabler = NewEnabler(RecordCalls(calls));

            enabler.NotifyCaptureLossSuspected();

            AssertCallSequence(calls);
            Assert.Equal(1, enabler.ReassertCount);
        }

        [Fact, Trait("Category", "wrc-04")]
        public void NativeStructLayoutsMatchWindowsX64Abi()
        {
            if (!Environment.Is64BitProcess)
            {
                return;
            }

            Assert.Equal(0, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.Version)).ToInt32());
            Assert.Equal(4, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.EnableProperty)).ToInt32());
            Assert.Equal(8, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.ControlFlags)).ToInt32());
            Assert.Equal(12, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.SourceId)).ToInt32());
            Assert.Equal(32, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.EnableFilterDesc)).ToInt32());
            Assert.Equal(40, Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.FilterDescCount)).ToInt32());
            Assert.Equal(16, Marshal.SizeOf<EVENT_FILTER_DESCRIPTOR>());
        }

        private static RegistryCaptureEnabler NewEnabler(RegistryCaptureEnabler.NativeEnableTraceEx2 native)
        {
            return new RegistryCaptureEnabler(TestHandle, ProviderId, TestMask, native, (message, level) => { });
        }

        private static RegistryCaptureEnabler.NativeEnableTraceEx2 RecordCalls(List<NativeCall> calls)
        {
            return (
                ulong handle,
                in Guid provider,
                uint controlCode,
                byte level,
                ulong anyKeyword,
                ulong allKeyword,
                int timeout,
                in ENABLE_TRACE_PARAMETERS parameters) =>
            {
                calls.Add(new NativeCall
                {
                    TraceHandle = handle,
                    ProviderId = provider,
                    ControlCode = controlCode,
                    Level = level,
                    MatchAnyKeyword = anyKeyword,
                    MatchAllKeyword = allKeyword,
                    Timeout = timeout,
                    Version = parameters.Version,
                    FilterDescCount = parameters.FilterDescCount
                });
                return 0;
            };
        }

        private static void AssertCallSequence(IReadOnlyList<NativeCall> calls)
        {
            Assert.Equal(2, calls.Count);

            NativeCall disable = calls[0];
            Assert.Equal(TestHandle, disable.TraceHandle);
            Assert.Equal(ProviderId, disable.ProviderId);
            Assert.Equal(0u, disable.ControlCode);
            Assert.Equal(0, disable.Level);
            Assert.Equal(0ul, disable.MatchAnyKeyword);
            Assert.Equal(0ul, disable.MatchAllKeyword);
            Assert.Equal(10000, disable.Timeout);
            Assert.Equal(2u, disable.Version);
            Assert.Equal(0, disable.FilterDescCount);

            NativeCall enable = calls[1];
            Assert.Equal(TestHandle, enable.TraceHandle);
            Assert.Equal(ProviderId, enable.ProviderId);
            Assert.Equal(1u, enable.ControlCode);
            Assert.Equal(5, enable.Level);
            Assert.Equal(TestMask, enable.MatchAnyKeyword);
            Assert.Equal(0ul, enable.MatchAllKeyword);
            Assert.Equal(10000, enable.Timeout);
            Assert.Equal(2u, enable.Version);
            Assert.Equal(1, enable.FilterDescCount);
        }

        private sealed class FakeSessionHandle
        {
            public ulong DangerousGetHandle()
            {
                return TestHandle;
            }
        }

        private sealed class NativeCall
        {
            public ulong TraceHandle { get; set; }
            public Guid ProviderId { get; set; }
            public uint ControlCode { get; set; }
            public byte Level { get; set; }
            public ulong MatchAnyKeyword { get; set; }
            public ulong MatchAllKeyword { get; set; }
            public int Timeout { get; set; }
            public uint Version { get; set; }
            public int FilterDescCount { get; set; }
        }
    }
}
