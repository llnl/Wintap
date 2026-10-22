/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using Microsoft.Diagnostics.Tracing;
using System;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using System.Linq;
using System.Runtime.Remoting;
using System.Diagnostics;
using com.espertech.esper.compat;
using Microsoft.Diagnostics.Tracing.StackSources;
using gov.llnl.wintap.platform.windows.collect.shared;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    /// <summary>
    /// WMI events from user mode logger
    /// </summary>
    internal class WMISensor : EtwProviderCollector
    {
        public WMISensor() : base()
        {
            SensorName = "Microsoft-Windows-WMI-Activity";
            EtwProviderId = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
        }

        public override void Process_Event(TraceEvent obj)
        {
            base.Process_Event(obj);
            WintapMessage msg = new WintapMessage(obj.TimeStamp, obj.ProcessID, WintapMessage.MessageTypeEnum.WMI);
            if (obj.PayloadNames.Contains("CorrelationId"))
            {
                msg.CorrelationId = obj.PayloadStringByName("CorrelationId");
            }
            if (obj.PayloadNames.Contains("ActivityId"))
            {
                msg.ActivityId = obj.PayloadStringByName("ActivityId");
            }
            msg.WMI = new WintapMessage.WmiActivityObject() { ClientProcessId = -1, CommandLine = "", IsLocal = true, CreatedProcessId = -1, Operation = "", OperationId = -1, ProcessName = "", ResultCode = 0, User = "" };
            try
            {
                if (obj.PayloadNames.Contains("Operation"))
                {
                    msg.WMI.Operation = obj.PayloadByName("Operation").ToString();
                }
                if (obj.PayloadNames.Contains("User"))
                {
                    msg.WMI.User = obj.PayloadByName("User").ToString();
                }
                if (obj.PayloadNames.Contains("IsLocal"))
                {
                    msg.WMI.IsLocal = bool.Parse(obj.PayloadByName("IsLocal").ToString());
                }
                if (obj.PayloadNames.Contains("ClientProcessId"))
                {
                    msg.WMI.ClientProcessId = Convert.ToInt32(obj.PayloadByName("ClientProcessId").ToString().Replace(",", ""));
                }
                if (obj.PayloadNames.Contains("OperationId"))
                {
                    msg.WMI.OperationId = Convert.ToInt32(obj.PayloadByName("OperationId").ToString().Replace(",", ""));
                }
                if (obj.PayloadNames.Contains("ResultCode"))
                {
                    msg.WMI.ResultCode = Convert.ToInt32(obj.PayloadByName("ResultCode"));
                }
                if (obj.PayloadNames.Contains("Commandline"))
                {
                    msg.WMI.CommandLine = obj.PayloadStringByName("Commandline");
                }
                if (obj.PayloadNames.Contains("CreatedProcessId"))
                {
                    msg.WMI.CreatedProcessId = Convert.ToInt32(obj.PayloadStringByName("CreatedProcessId").Replace(",", ""));
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error parsing user mode event: " + ex.Message, LogLevel.Debug);
            }
            EventChannel.Send(msg);
        }

        private void parseWmiEvent(TraceEvent obj, int eventId)
        {
            try
            {
                WintapMessage msg = new WintapMessage(obj.TimeStamp, obj.ProcessID, WintapMessage.MessageTypeEnum.WMI);
                msg.WMI = new WintapMessage.WmiActivityObject();
                if (eventId == 11)
                {
                    msg.WMI.Operation = obj.PayloadByName("Operation").ToString();
                    msg.WMI.User = obj.PayloadByName("User").ToString();
                    msg.WMI.IsLocal = bool.Parse(obj.PayloadStringByName("IsLocal"));
                    msg.PID = Convert.ToInt32(obj.PayloadByName("ClientProcessId"));
                }

                msg.WMI.OperationId = Convert.ToInt32(obj.PayloadByName("OperationId"));
                msg.ActivityType = WintapMessage.ActivityTypeEnum.Start;
                if (eventId == 13)
                {
                    msg.ActivityType = WintapMessage.ActivityTypeEnum.Stop;
                    msg.WMI.ResultCode = Convert.ToInt32(obj.PayloadByName("ResultCode"));
                }

                msg.WMI.ProcessName = "NA";
                try
                {
                    msg.WMI.ProcessName = Process.GetProcessById(msg.PID).ProcessName;
                }
                catch (Exception ex) { }
                EventChannel.Send(msg);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error processing wmi activity event from ETW: " + ex.Message, LogLevel.Debug);
            }
        }
    }
}
