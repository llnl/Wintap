using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static gov.llnl.wintap.collect.models.WintapMessage;

namespace gov.llnl.wintap.platform.windows.collect.etw
{

    internal class MemoryMapSensor : EtwProviderCollector
    {
        Dictionary<string, CommitInfo> commitHistory;
        private Stopwatch refreshTimer;
        private bool isStarting;
        private bool scanInProgress;
        private long scanErrors;

        [DllImport("psapi.dll")]
        static extern bool EnumProcessModules(nint hProcess, [Out] nint[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll")]
        static extern bool GetMappedFileNameA(nint hProcess, uint lpv, string lpFilename, uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern uint GetModuleFileNameEx(nint hProcess, nint hModule, StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualQueryEx(nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        static extern nint OpenFileMapping(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll")]
        static extern nint MapViewOfFile(nint hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, nuint dwNumberOfBytesToMap);

        [DllImport("kernel32.dll")]
        static extern bool UnmapViewOfFile(nint lpBaseAddress);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(nint hObject);
        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(
        nint hProcess,
        nint lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

        static extern bool GetFileInformationByHandleEx(nint hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, out FILE_NAME_INFO lpFileInformation, uint dwBufferSize);


        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public nint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FILE_NAME_INFO
        {
            public uint FileNameLength;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string FileName;
        }

        enum FILE_INFO_BY_HANDLE_CLASS
        {
            FileNameInfo = 9
        }


        public MemoryMapSensor() : base()
        {
            SensorName = "Microsoft-Windows-Kernel-Memory";
            EtwProviderId = "D1D93EF7-E1F2-4F45-9943-03D245FE6C00";
            commitHistory = new Dictionary<string, CommitInfo>();
        }

        public override bool Start()
        {
            WintapLogger.Log.Append(SensorName + " is starting...", LogLevel.Info);
            base.Start();
            refreshTimer = new Stopwatch();
            refreshTimer.Start();
            isStarting = true;
            bool status = true;
            scanInProgress = false;

            string sql = "select * from WintapMessage where CAST(MessageType, string)='Process' AND CAST(ActivityType, string)='Start'";
            var epQuery = EventChannel.CompileDeploy(sql, "MEMORY_MAPCollector").Statements[0];
            epQuery.Events += EpQuery_Events;

            WintapLogger.Log.Append(SensorName + " started", LogLevel.Info);

            return status;
        }

        public override void Process_Event(TraceEvent obj)
        {
            base.Process_Event(obj);
            try
            {
                switch (obj.EventName)
                {
                    case "MemInfoWS":
                        if (obj.PayloadNames.Contains("WSCommitInfo"))
                        {
                            string commitInfoString = obj.PayloadStringByName("WSCommitInfo");
                            List<CommitInfo> commitInfos = JsonConvert.DeserializeObject<List<CommitInfo>>(commitInfoString);

                            // scan-on-change continously
                            if (!scanInProgress)
                            {
                                scanInProgress = true;
                                DateTime sweepStartTime = DateTime.Now;
                                int totalProcessScanCount = detectChanges(commitInfos, obj.TimeStamp);
                                scanInProgress = false;
                            }                    
                        }
                        break;
                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("WARN problem parsing user mode event: " + ex.Message, LogLevel.Info);
                scanInProgress = false;
            }
        }

        private void EpQuery_Events(object sender, UpdateEventArgs e)
        {
            try
            {
                WintapMessage newProcess = (WintapMessage)e.NewEvents[0].Underlying;
                ProcessRecord newPR = new ProcessRecord() { ProcessId = newProcess.PID, CommandLine = newProcess.Process.CommandLine, CreateTime = DateTime.FromFileTimeUtc(newProcess.EventTime), ProcessPath = newProcess.Process.Path, ParentPidHash = newProcess.Process.ParentPidHash, PidHash = newProcess.PidHash, ParentProcessId = newProcess.Process.ParentPID, ProcessName = newProcess.ProcessName };
                refreshSnapshot(newPR);

            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("WARN problem scanning memory for new process: " + ex.Message, LogLevel.Info);
            }
        }
        private bool processRunning(int pid)
        {
            try
            {
                Process process = Process.GetProcessById(pid);
                if (process != null)
                {
                    return true;
                }
            }
            catch (ArgumentException)
            {

            }

            return false;
        }

        private int detectChanges(List<CommitInfo> commitInfos, DateTime eventTime)
        {
            scanInProgress = true;
            int scanCount = 0;
            foreach (CommitInfo currentInfo in commitInfos)
            {
                try
                {
                    ProcessRecord owningProcess = EventChannel.GetProcessHistory(currentInfo.ProcessId, DateTime.Now);
                    if (owningProcess.ProcessName != "unknown")
                    {
                        string pidHash = owningProcess.PidHash;
                        // do we have an existing commit history for this process?
                        if (commitHistory.Count(ch => ch.Key == pidHash) > 0)
                        {
                            // yes, so look for changes and trigger MEMORY_MAP snapshot refresh
                            ulong lastProcessPageCount = Convert.ToUInt64(commitHistory.Where(c => c.Key == pidHash).FirstOrDefault().Value.WorkingSetPageCount);
                            ulong currentProcessPageCount = Convert.ToUInt64(currentInfo.WorkingSetPageCount);

                            if (lastProcessPageCount != currentProcessPageCount)
                            {
                                commitHistory[pidHash] = currentInfo;
                                refreshSnapshot(owningProcess);
                                scanCount++;
                            }
                        }
                        else
                        {
                            // no, so initialize process state
                            commitHistory.Add(pidHash, currentInfo);
                            refreshSnapshot(owningProcess);
                        }
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append("WARN problem scanning memory:  " + ex.Message, LogLevel.Info);
                }
            }
            scanInProgress = false;

            // clean up history
            // Materialize keys before removal; mutating Values during enumeration
            // aborted sweeps as soon as a historical process had exited.
            var deadProcessKeys = commitHistory
                .Where(kvp => !processRunning(kvp.Value.ProcessId))
                .Select(kvp => kvp.Key)
                .ToList();
            foreach (var key in deadProcessKeys)
                commitHistory.Remove(key);
            return scanCount;
        }

        private void refreshSnapshot(ProcessRecord _owningProcess)
        {
            if (!processRunning(_owningProcess.ProcessId)) { return; }
            if (_owningProcess.ProcessName == "devenv.exe") { return; }
            if (_owningProcess.ProcessId < 200) { return; }  // skip protected processes
            DateTime startScanTime = DateTime.Now;
            Process process = Process.GetProcessById(_owningProcess.ProcessId);
            nint baseAddress = new nint(0);

            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            while (true)
            {
                try
                {
                    memInfo = new MEMORY_BASIC_INFORMATION();
                    bool bytesRead = VirtualQueryEx(process.Handle, baseAddress, out memInfo, (uint)Marshal.SizeOf(memInfo));
                    if (bytesRead == false)
                    {
                        break;
                    }

                    WintapMessage wm = new WintapMessage(DateTime.Now, _owningProcess.ProcessId, MessageTypeEnum.MemoryMap);
                    wm.PidHash = _owningProcess.PidHash;
                    wm.ProcessName = _owningProcess.ProcessName;
                    // get what state the memory region is in (commmit, reserve, free)
                    if(memInfo.State == 4096)
                    {
                        wm.ActivityType = ActivityTypeEnum.MemCommit;
                    }
                    else if(memInfo.State == 8192)
                    {
                        wm.ActivityType = ActivityTypeEnum.MemReserve;
                    }
                    else if(memInfo.State == 65536)
                    {
                        wm.ActivityType = ActivityTypeEnum.MemFree;
                    }
                    wm.MemoryMap = new MemoryMapData();
                    wm.MemoryMap.AllocationBaseAddress = memInfo.AllocationBase.ToInt64().ToString("X");
                    wm.MemoryMap.AllocationProtect = ((WintapMessage.PageProtectEnum)memInfo.AllocationProtect);
                    wm.MemoryMap.PageType = ((WintapMessage.PageTypeEnum)memInfo.Type); // get what kind of memory it is (image, mapped, private)
                    wm.MemoryMap.BaseAddress = memInfo.BaseAddress.ToString("X");
                    wm.MemoryMap.RegionSize = memInfo.RegionSize.ToInt64();
                    wm.MemoryMap.PageProtect = ((PageProtectEnum)memInfo.Protect);
                    wm.MemoryMap.MZHeaderPresent = false;

                    if ((PageTypeEnum)memInfo.Type == PageTypeEnum.MEM_IMAGE)
                    {
                        StringBuilder path = new StringBuilder(1024);
                        uint size = GetModuleFileNameEx(process.Handle, memInfo.BaseAddress, path, 1024);
                        if (size > 0)
                        {
                            wm.MemoryMap.Description = path.ToString();
                        }
                    }

                    byte[] buffer = new byte[2];
                    int bytesRead2;
                    bool success = ReadProcessMemory(process.Handle, baseAddress, buffer, buffer.Length, out bytesRead2);
                    if (success && bytesRead2 == 2)
                    {
                        if (buffer[0] == 'M' && buffer[1] == 'Z')
                        {
                            wm.MemoryMap.MZHeaderPresent = true;
                        }
                    }

                    baseAddress = new nint(memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64());
                    wm.AgentId = StateManager.AgentId.ToString();
                    EventChannel.InspectForHealth(wm);
                    EventChannel.EsperRuntime.EventService.SendEventBean(wm, "WintapMessage");  // call esper direct since we do not require pidhash lookup.
                }
                catch
                {
                    scanErrors++;
                    WintapLogger.Log.Append("WARN problem performing memory scan of: " + _owningProcess.ProcessName, LogLevel.Info);
                    baseAddress = new nint(memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64());
                    if (baseAddress.ToInt64() == 0) { break; }
                }

            }
        }
    }

    internal class CommitInfo
    {
        [JsonProperty("ProcessID")]
        internal int ProcessId { get; set; }

        [JsonProperty("WorkingSetPageCount")]
        internal string WorkingSetPageCount { get; set; }

        [JsonProperty("CommitPageCount")]
        internal string CommitPageCount { get; set; }

        [JsonProperty("VirtualSizeInPages")]
        internal string VirtualSizeInPages { get; set; }

        [JsonProperty("PrivateWorkingSetPageCount")]
        internal string PrivateWorkingSetPageCount { get; set; }

        [JsonProperty("StoreSizePageCount")]
        internal string StoreSizePageCount { get; set; }

        [JsonProperty("StoredPageCount")]
        internal string StoredPageCount { get; set; }

        [JsonProperty("CommitDebtInPages")]
        internal string CommitDebtInPages { get; set; }

        [JsonProperty("SharedCommitInPages")]
        internal string SharedCommitInPages { get; set; }
    }

}
