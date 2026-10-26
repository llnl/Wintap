/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.client;
using com.espertech.esper.common.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.transform;
using System;
using System.Dynamic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Timers;
using System.IO;

namespace gov.llnl.wintap.core.etl.extract
{
    internal class ProcessSerializer : Serializer
    {
        //internal enum ProcessActivityEnum { START, STOP, REFRESH };
        private string diagnosticProcessName;
        private int diagnosticProcessCounter;
        private HostId host;

        internal ProcessSerializer(string query) : base(query)
        {
            host = HostSerializer.Instance.HostId;
            diagnosticProcessName = "NONE";
            diagnosticProcessCounter = 0;
        }

        internal void Stop()
        {
            WintapLogger.Log.Append("ProcessSerializer Stop called.", LogLevel.Info);
        }

        protected override void HandleSensorEvent(EventBean sensorEvent)
        {
            try
            {
                WintapMessage wintapMessage = (WintapMessage)sensorEvent.Underlying;

                if (wintapMessage.MessageType == WintapMessage.MessageTypeEnum.Process && (wintapMessage.ActivityType == WintapMessage.ActivityTypeEnum.Start || wintapMessage.ActivityType == WintapMessage.ActivityTypeEnum.Refresh))
                {
                    handleStartEvent(wintapMessage);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Top level error in process event handler: " + ex.Message, LogLevel.Debug);
            }
        }

        private void handleStartEvent(WintapMessage wintapMessage)
        {
            ProcessStartData procWD = createProcessObject(wintapMessage.PID, wintapMessage.Process.ParentPID, wintapMessage.EventTime, wintapMessage.Process.Path, wintapMessage.Process.CommandLine, wintapMessage.Process.User, wintapMessage.Process.MD5, wintapMessage.Process.SHA2, wintapMessage.MessageType.ToString(), wintapMessage.Process.CommandLine, wintapMessage.PidHash, wintapMessage.Process.ParentPidHash, wintapMessage.ActivityType.ToString(), wintapMessage.AgentId);
            procWD.Hostname = host.Hostname;
            ApplyStartProvenance(procWD, wintapMessage.Process.Arguments);

            try
            {
                dynamic flatMsg = (ExpandoObject)procWD.ToDynamic();
                this.Save(flatMsg);
                flatMsg = null;
                wintapMessage = null;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("ERROR saving flattened START event:  " + ex.Message, LogLevel.Info);
            }
        }

        internal static void ApplyStartProvenance(ProcessStartData data, string arguments)
        {
            var sources = (arguments ?? "").Split((char[])null, StringSplitOptions.RemoveEmptyEntries)
                .Where(token => token.StartsWith("PROC_START_SRC=", StringComparison.Ordinal))
                .Select(token => token.Substring("PROC_START_SRC=".Length)).Distinct().ToArray();
            // Conflicting or unknown breadcrumbs must not falsely classify a
            // repeated Start. Persist only the bounded producer vocabulary.
            data.ProcessStartSource = sources.Length == 1 &&
                (sources[0] == "sched_fork" || sources[0] == "sched_exec" || sources[0] == "execve_or_execveat")
                ? sources[0] : null;
        }

        private ProcessStartData createProcessObject(int pid, int parentPid, long eventTime, string path, string commandLine, string user, string md5, string sha2, string msgType, string cmdline, string pidHash, string parentPidHash, string activityType, string agentId)
        {
            ProcessStartData procWD = new ProcessStartData(parentPidHash, parentPid, pid, pidHash, parseProcessName(path), eventTime, path, user, getSIDForUser(user), md5, sha2,cmdline, agentId);
            procWD.ActivityType = activityType;
            procWD.Hostname = host.Hostname;
            return procWD;
        }

        private string parseProcessName(string path)
        {
            string procName = "PARSE_ERROR";
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    return "unknown";
                }

                // Handle both Windows (\) and Linux (/) separators.
                procName = path.Replace('\\', '/').Split(new char[] { '/' }).Last();
                procName = procName.ToLowerInvariant();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("error parsing process name: " + ex.Message, LogLevel.Debug);
            }
            return procName;
        }

private string getSIDForUser(string userName)
{
    string sid = "NA";
    
    if (String.IsNullOrEmpty(userName) || userName.ToLower() == "na")
    {
        return sid;
    }

    try
    {
        // Check if we're on Windows
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            NTAccount nt = new NTAccount(userName);
            sid = nt.Translate(typeof(SecurityIdentifier)).Value.ToString();
        }
        else
        {
            // On Linux, get UID instead of Windows SID
            sid = GetLinuxUID(userName);
        }
    }
    catch (Exception ex)
    {
        WintapLogger.Log.Append(
            $"Error getting SID/UID for user: {userName}, msg: {ex.Message}", 
            LogLevel.Debug);
    }
    
    return sid;
}

private string GetLinuxUID(string userName)
{
    try
    {
        // Option 1: Use /etc/passwd parsing
        var passwdLines = File.ReadAllLines("/etc/passwd");
        var userLine = passwdLines.FirstOrDefault(line => 
            line.StartsWith($"{userName}:"));
        
        if (userLine != null)
        {
            var parts = userLine.Split(':');
            if (parts.Length >= 3)
            {
                return parts[2]; // UID is the 3rd field
            }
        }
        
        // Option 2: Use 'id' command as fallback
        // GrantJ - this seems to fail and recursively call id for the unknown-3 string...
        // var process = new System.Diagnostics.Process
        // {
        //     StartInfo = new System.Diagnostics.ProcessStartInfo
        //     {
        //         FileName = "id",
        //         Arguments = $"-u {userName}",
        //         RedirectStandardOutput = true,
        //         UseShellExecute = false,
        //         CreateNoWindow = true
        //     }
        // };
        
        // process.Start();
        // string output = process.StandardOutput.ReadToEnd().Trim();
        // process.WaitForExit();
        
        // if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
        // {
        //     return output;
        // }
    }
    catch (Exception ex)
    {
        WintapLogger.Log.Append(
            $"Error getting Linux UID for user: {userName}, msg: {ex.Message}", 
            LogLevel.Debug);
    }
    
    return "NA";
}
    }
}
