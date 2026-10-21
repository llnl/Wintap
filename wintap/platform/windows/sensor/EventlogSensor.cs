/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.platform.windows.collect.shared;
using Newtonsoft.Json;
using System;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    /// <summary>
    /// Sipmle collector for the Windows event logs (System, Application, Security)
    /// </summary>
    internal class EventlogSensor : EtwProviderCollector
    {
        public EventlogSensor() : base()
        {
            SensorName = "EventLogEvent";
            EtwProviderId = "none";
        }

        public override bool Start()
        {
            base.Start();
            try
            {
                var appQuery = new EventLogQuery("Application", PathType.LogName);
                EventLogWatcher appWatcher = new EventLogWatcher(appQuery);
                appWatcher.EventRecordWritten += logWatcher_EventRecordWritten;
                appWatcher.Enabled = true;

                var sysQuery = new EventLogQuery("System", PathType.LogName);
                EventLogWatcher sysWatcher = new EventLogWatcher(sysQuery);
                sysWatcher.EventRecordWritten += logWatcher_EventRecordWritten;
                sysWatcher.Enabled = true;

                var secQuery = new EventLogQuery("Security", PathType.LogName);
                EventLogWatcher secWatcher = new EventLogWatcher(secQuery);
                secWatcher.EventRecordWritten += logWatcher_EventRecordWritten;
                secWatcher.Enabled = true;

            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Problem starting collector: " + this.SensorName + ", error: " + ex.Message, LogLevel.Always);
            }
            return true;
        }

        private void logWatcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            sendEvent(e.EventRecord);
        }

        private void sendEvent(EventRecord entry)
        {
            int pid = 0; // default value for older OSes that don't support the ProcessId record property.
            try
            {
                pid = entry.ProcessId.Value;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Could not get PID for event log record, defaulting to {pid}   error: " + ex.Message, LogLevel.Debug);
            }
            WintapMessage msg = new WintapMessage(entry.TimeCreated.Value, pid, WintapMessage.MessageTypeEnum.EventLogEvent);
            msg.ActivityType = WintapMessage.ActivityTypeEnum.EventWritten;
            msg.EventLogEvent = new WintapMessage.EventlogEventObject();
            msg.EventLogEvent.EventId = entry.Id;
            msg.EventLogEvent.EventMessage = ConvertXmlToJson(entry.ToXml());
            msg.EventLogEvent.LogName = entry.LogName;
            msg.EventLogEvent.LogSource = entry.ProviderName;
            EventChannel.Send(msg);
        }

        static string ConvertXmlToJson(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);

            return JsonConvert.SerializeXmlNode(doc, Newtonsoft.Json.Formatting.Indented, omitRootObject: true);
        }
    }
}
