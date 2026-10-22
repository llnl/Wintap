/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using System.Runtime.InteropServices;
using gov.llnl.wintap.platform.windows.collect.shared;
using System;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.collect.models;
using System.Diagnostics;
using System.IO;
using Newtonsoft.Json;
using System.Linq;
using gov.llnl.wintap.core.shared;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    /// <summary>
    /// System Event Notification Services (SENS) collector
    /// SENS:  https://docs.microsoft.com/en-us/windows/win32/sens/notifications
    /// </summary>
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    public class SensSensor : BaseWindowsSensor, SensEvents.ISensLogon
    {
        public SensSensor() : base()
        {
            this.SensorName = "SENS";
        }

        public override bool Start()
        {
            dynamic comAdmin = Activator.CreateInstance(Type.GetTypeFromProgID("COMAdmin.COMAdminCatalog", throwOnError: true));
            try
            {
                dynamic subCollection = comAdmin.GetCollection("TransientSubscriptions");
                SubscribeToEvent(subCollection, "DisplayUnlock", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "DisplayLock", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "Logon", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "Logoff", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "StartScreenSaver", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "StopScreenSaver", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
                SubscribeToEvent(subCollection, "StartShell", "{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}");
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("error registering SENS events: " + ex.Message, LogLevel.Info);
                return false;
            }
            finally
            {
                Marshal.FinalReleaseComObject(comAdmin);
            }
            WintapLogger.Log.Append("SENS subscriptions registered", LogLevel.Info);
            return true;
        }

        public void DisplayLock(string userName)
        {
            sendSessionChangeEvent("ScreenLock", userName);
        }
        public void DisplayUnlock(string userName)
        {
            sendSessionChangeEvent("ScreenUnlock", userName);
        }
        public void StartScreenSaver(string userName)
        {
            sendSessionChangeEvent("ScreenSaverStart", userName);
        }
        public void StopScreenSaver(string userName)
        {
            sendSessionChangeEvent("ScreenSaverStop", userName);
        }
        public void StartShell(string userName)
        {
            sendSessionChangeEvent("ShellStart", userName);
        }

        public void Logon(string userName)
        {
            sendSessionChangeEvent("Logon", userName);
        }
        public void Logoff(string userName)
        {
            sendSessionChangeEvent("LogOff", userName);
        }

        private void SubscribeToEvent(dynamic subCollection, string methodName, string guidString)
        {
            dynamic catalogObject = subCollection.Add();
            catalogObject.Value["EventCLSID"] = guidString;
            catalogObject.Value["Name"] = "Subscription to " + methodName + " event";
            catalogObject.Value["MethodName"] = methodName;
            catalogObject.Value["SubscriberInterface"] = this;
            catalogObject.Value["Enabled"] = true;
            subCollection.SaveChanges();
        }
        private void sendSessionChangeEvent(string description, string userName)
        {
            this.Counter++;
            WintapMessage msg = new WintapMessage(DateTime.Now, 4, WintapMessage.MessageTypeEnum.SessionChange);
            msg.ReceiveTime = DateTime.Now.ToFileTimeUtc();
            msg.SessionChange = new WintapMessage.SessionChangeObject() { UserName = userName, Description = description };
            EventChannel.Send(msg);
            WintapLogger.Log.Append("    User: " + userName + "  description: " + description, LogLevel.Info);
        }

    }
}
