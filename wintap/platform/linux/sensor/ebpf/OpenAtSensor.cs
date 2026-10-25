/*
 * MOVED INTO THE FILEOPSSENSOR!!! 
 */

using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// eBPF-based file access sensor using openat() syscall tracepoint
    /// </summary>
    internal class OpenatSensor : BaseEbpfSensor
    {
        private ProcessHash _pidHashGenerator;

        protected override string BpfObjectFileName => "openat_tracer.bpf.o";
        protected override string BpfProgramName => "trace_openat_entry";

        internal OpenatSensor()
        {
            SensorName = "OpenatFile";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback()
        {
            return HandleEvent;
        }

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var evt = Marshal.PtrToStructure<OpenatEvent>(data);
                
                string rawComm = evt.GetComm() ?? "null";
                string rawFilename = evt.GetFilename() ?? "null";
                WintapLogger.Log.Append(
                    $"OpenatSensor RAW EVENT: pid={evt.Pid}, comm='{rawComm}', filename='{rawFilename}'", 
                    LogLevel.Debug
                );
                
                // Defensive null check
                if (evt.Comm == null || evt.Filename == null)
                {
                    WintapLogger.Log.Append($"OpenatSensor: NULL data in event", LogLevel.Warn);
                    return 0;
                }

                string filePath = evt.GetFilename();
                
                // Skip if no path
                if (string.IsNullOrEmpty(filePath))
                {
                    WintapLogger.Log.Append($"OpenatSensor: Empty filename from PID {evt.Pid}", LogLevel.Debug);
                    return 0;
                }
                
                WintapLogger.Log.Append(
                    $"OpenatSensor: Processing '{filePath}' from PID {evt.Pid} ({rawComm})", 
                    LogLevel.Debug
                );
                
                // Skip .etl files (feedback loop prevention like FileSensor)
                if (filePath.EndsWith(".etl"))
                {
                    WintapLogger.Log.Append($"OpenatSensor: Filtered .etl file: {filePath}", LogLevel.Debug);
                    return 0;
                }

                // Create WintapMessage matching FileSensor.sendFileEvent() pattern
                var message = new WintapMessage(
                    DateTime.UtcNow,
                    (int)evt.Pid,
                    WintapMessage.MessageTypeEnum.File
                );

                message.ActivityType = WintapMessage.ActivityTypeEnum.Open;
                
                message.File = new WintapMessage.FileActivityObject
                {
                    Path = filePath.ToLower(),  // FileSensor uses lowercase
                    BytesRequested = 0,         // Not available for openat
                    PID = (int)evt.Pid
                };

                // Set ActivityId and CorrelationId (required for File events)
                message.ActivityId = "";
                message.CorrelationId = "";

                // File-event time is not process-start time. Core resolves attribution.
                message.PidHash = "";
                message.ProcessName = evt.GetComm() ?? "unknown";

                WintapLogger.Log.Append(
                    $"OpenatSensor: Sending file event: {filePath}", 
                    LogLevel.Debug
                );

                EventChannel.Send(message);
                
                WintapLogger.Log.Append(
                    $"OpenatSensor: Successfully sent event for {filePath}", 
                    LogLevel.Debug
                );
                
                return 0;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} event handler error: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"{SensorName} stack trace: {ex.StackTrace}", LogLevel.Debug);
                return -1;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct OpenatEvent
    {
        public uint Pid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Comm;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] Filename;

        public string GetComm() => StructHelper.GetString(Comm);
        public string GetFilename() => StructHelper.GetString(Filename);
    }
}
