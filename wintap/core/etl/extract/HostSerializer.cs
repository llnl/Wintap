/*
* Copyright (c) 2022, Lawrence Livermore National Security, LLC.
* Produced at the Lawrence Livermore National Laboratory.
* All rights reserved.
*/

using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.infrastructure;
using Microsoft.Win32;
using Parquet;
using Parquet.Schema;
using Parquet.Serialization;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Timers;

namespace gov.llnl.wintap.core.etl.extract
{
    /// <summary>
    /// General host and network configuration
    /// </summary>
    internal class HostSerializer
    {
        private HostId hostId;
        private string etlRoot;

        internal HostId HostId
        {
            get { return hostId; }
        }

        internal HostData hostContainer;
        internal HostData HostContainer
        {
            get { return hostContainer; }
        }

        private static HostSerializer localhost;
        internal static HostSerializer Instance
        {
            get
            {
                if (localhost == null)
                {
                    localhost = new HostSerializer();
                }

                return localhost;
            }
        }

        internal HostData GetSendableHost()
        {
            HostData hostObject = HostSerializer.Instance.HostContainer;
            hostObject.Hostname = HostSerializer.Instance.HostId.Hostname;
            hostObject.EventTime = ((System.DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
            hostObject.MessageType = "Host";
            return hostObject;
        }

        private HostSerializer()
        {
            hostId = new HostId();
            etlRoot = gov.llnl.wintap.core.etl.shared.Utilities.GetFileStorePath("host");
            hostId.Hostname = Environment.MachineName;
            hostContainer = getHost();
        }

        /// <summary>
        /// Send up any host-level changes and check-in with a current "EventTime"
        /// </summary>
        internal async void WriteHostRecord()
        {
            try
            {
                HostData host = new HostData();
                host.Hostname = Computer.Get().Name;
                host.Arch = "64-bit";
                if (!Environment.Is64BitOperatingSystem) { host.Arch = "32-bit"; }
                host.OS = Computer.Get().OSName;
                host.OSVersion = Computer.Get().OSVersion;
                host.EventTime = ((System.DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
                host.ProcessorCount = Computer.Get().ProcessorCount;
                host.ProcessorSpeed = Computer.Get().ProcessorSpeed;
                host.LastBoot = Computer.Get().LastBoot;
                host.HasBattery = Computer.Get().HasBattery;
                host.Domain = Computer.Get().Domain;
                host.DomainRole = Computer.Get().DomainRole;
                host.WintapVersion = Assembly.GetEntryAssembly().GetName().Version.ToString();
                host.ETLVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                host.MessageType = "Host";
                host.AgentId = Utilities.GetAgentId();

                string hostFile = "host-" + DateTime.UtcNow.ToFileTimeUtc() + ".parquet";
                DirectoryInfo hostDir = new DirectoryInfo(this.etlRoot);
                if (!hostDir.Exists)
                {
                    hostDir.Create();
                }
                hostFile = Path.Combine(hostDir.FullName, hostFile);
                ParquetSchema schema = DetermineSchemaFromExpando(host.ToDynamic());

                ParquetOptions options = new ParquetOptions();
                options.CompressionMethod = gov.llnl.wintap.core.etl.load.ParquetWriter.GetCompressionMethod();
                List<ExpandoObject> data = new List<ExpandoObject>();
                data.Add(host.ToDynamic());

                using (var fileStream = new FileStream(hostFile, FileMode.Create, FileAccess.Write))
                {
                    await ParquetSerializer.SerializeUntypedAsync(data.Cast<IDictionary<string, object>>().ToList(), schema, fileStream, options);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("error creating host record: " + ex.Message, LogLevel.Info);
            }

        }



        /// <summary>
        /// Send up any changes to Mac/Ip configurations
        /// </summary>
        internal async void WriteMacIPRecords()
        {
            try
            {
                var macIps = gov.llnl.wintap.core.etl.shared.Utilities.GetMacIps();
                string macIpFile = "macip-" + DateTime.UtcNow.ToFileTimeUtc() + ".parquet";
                DirectoryInfo macIpDir = new DirectoryInfo(gov.llnl.wintap.core.etl.shared.Utilities.GetFileStorePath("macip"));
                if (!macIpDir.Exists)
                {
                    macIpDir.Create();
                }
                macIpFile = Path.Combine(macIpDir.FullName, macIpFile);
                foreach (MacIpV4Record macIp in macIps)
                {
                    ParquetSchema schema = DetermineSchemaFromExpando(macIp.ToDynamic());

                    ParquetOptions options = new ParquetOptions();
                    options.CompressionMethod = gov.llnl.wintap.core.etl.load.ParquetWriter.GetCompressionMethod();
                    List<ExpandoObject> data = new List<ExpandoObject>();
                    foreach (MacIpV4Record macIpV4Record in macIps)
                    {
                        data.Add(macIpV4Record.ToDynamic());
                    }

                    using (var fileStream = new FileStream(macIpFile, FileMode.Create, FileAccess.Write))
                    {
                        await ParquetSerializer.SerializeUntypedAsync(data.Cast<IDictionary<string, object>>().ToList(), schema, fileStream, options);
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error creatig MacIp: " + ex.Message, LogLevel.Info);

            }
        }

        private static ParquetSchema DetermineSchemaFromExpando(ExpandoObject firstItem)
        {
            List<Field> fields = new List<Field>();
            foreach (var kvp in firstItem)
            {
                try
                {
                    Type type = kvp.Value?.GetType() ?? typeof(string);
                    DataField field = new DataField(kvp.Key, type);
                    fields.Add(field);
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Error on determining parquet schema: {ex}", LogLevel.Error);
                }
            }
            ParquetSchema schema = new ParquetSchema(fields.ToArray());
            return schema;
        }
        private HostData getHost()
        {
            HostData host = new HostData();
            host.OS = Environment.OSVersion.ToString();
            try
            {
                RegistryKey lm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                host.OS = lm.GetValue("ProductName").ToString();
            }
            catch { }
            host.Arch = "32-bit";
            if (Environment.Is64BitOperatingSystem)
            {
                host.Arch = "64-bit";
            }
            return host;
        }

    }
}
