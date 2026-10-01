/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using System;
using System.Linq;
using System.Timers;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using static gov.llnl.wintap.Interfaces;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using System.Diagnostics.Tracing;
using System.IO;
using System.Xml.Serialization;
using gov.llnl.wintap.core.etl.load.interfaces;
using gov.llnl.wintap.core.etl.model;
using Newtonsoft.Json;
using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.shared;
using Utilities = gov.llnl.wintap.core.etl.shared.Utilities;

namespace gov.llnl.wintap.core.etl
{
    internal class WintapETL
    {
        #region private fields
        private ProcessSerializer processSensor;
        private ProcessStopSerializer processStopSensor;
        private TcpConnectionSerializer tcpSensor;
        private UdpPacketSerializer udpSensor;
        private FileSerializer fileSensor;
        private RegistrySerializer regSensor;
        private FocusChangeSerializer fcSensor;
        private SELinuxSerializer selinuxSensor;
        private DefaultSerializer defaultSensor;
        private CacheManager cacheMgr;
        private List<Serializer> sensors;
        private DateTime lastNetChange;
        private readonly string esperNameSpacePrefix = "gov.llnl.wintap.core.etl.esper.";
        private long totalMessageCount;
        ETLConfig etlConfig;

        #endregion

        #region public methods

        public bool Start()
        {
            bool etlLoaded = false;
            try
            {
                etlConfig = Utilities.GetETLConfig();

                lastNetChange = DateTime.Now;
                BackgroundWorker processObjectModelWorker = new BackgroundWorker();
                processObjectModelWorker.DoWork += ProcessObjectModelWorker_DoWork;
                processObjectModelWorker.RunWorkerCompleted += ProcessObjectModelWorker_RunWorkerCompleted;
                processObjectModelWorker.RunWorkerAsync();

                BackgroundWorker cacheManagerThread = new BackgroundWorker();
                cacheManagerThread.DoWork += cacheManager_DoWork;
                cacheManagerThread.RunWorkerCompleted += cacheManager_RunWorkerCompleted;
                cacheManagerThread.RunWorkerAsync();

                Timer statsUpdateTimer = new Timer();
                statsUpdateTimer.Interval = 5000;
                statsUpdateTimer.AutoReset = true;
                statsUpdateTimer.Elapsed += StatsUpdateTimer_Elapsed;
                //statsUpdateTimer.Start();

                etlLoaded = true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Could not start ETL!!!: " + ex.Message, LogLevel.Info);
            }

            return etlLoaded;

        }


        public void Shutdown()
        {
            cacheMgr.Stop();
            processSensor.Stop();
            WintapLogger.Log.Append("shutdown complete", LogLevel.Info);
            WintapLogger.Log.Close();
        }

        #endregion

        #region private methods and event hanlders

        private void ProcessObjectModelWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            WintapLogger.Log.Append("Creating sensors", LogLevel.Info);
            defaultSensor = new DefaultSerializer(esperNameSpacePrefix + "default.epl");
            fileSensor = new FileSerializer(esperNameSpacePrefix + "file.epl");
            fcSensor = new FocusChangeSerializer(esperNameSpacePrefix + "focuschange.epl");
            regSensor = new RegistrySerializer(esperNameSpacePrefix + "registry.epl");
            selinuxSensor = new SELinuxSerializer(esperNameSpacePrefix + "selinux.epl");
            tcpSensor = new TcpConnectionSerializer(new string[] { esperNameSpacePrefix + "tcp.epl" });
            udpSensor = new UdpPacketSerializer(new string[] { esperNameSpacePrefix + "udp.epl" });
            sensors = new List<Serializer>();
            sensors.Add(defaultSensor);
            sensors.Add(processSensor);
            sensors.Add(processStopSensor);
            sensors.Add(fileSensor);
            sensors.Add(tcpSensor);
            sensors.Add(udpSensor);
            sensors.Add(regSensor);
            sensors.Add(fcSensor);
            sensors.Add(selinuxSensor);
            WintapLogger.Log.Append("All sensors created.  Serializer serialization interval (msec): " + etlConfig.SerializationIntervalSec, LogLevel.Info);
        }

        private void ProcessObjectModelWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            WintapLogger.Log.Append("Creating process sensors", LogLevel.Info);

            processSensor = new ProcessSerializer(esperNameSpacePrefix + "process.epl");
            processStopSensor = new ProcessStopSerializer(esperNameSpacePrefix + "process-stop.epl");
        }

        private void StatsUpdateTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            WintapLogger.Log.Append($"Total {Env.AppName} messages received: " + totalMessageCount, LogLevel.Info);
        }

        private void cacheManager_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            WintapLogger.Log.Append("initialization complete", LogLevel.Info);
        }

        private void cacheManager_DoWork(object sender, DoWorkEventArgs e)
        {
            WintapLogger.Log.Append($"creating ${Env.AppName} data cache manager", LogLevel.Info);
            List<IUpload> uploaders = new List<IUpload>();
            try
            {
                cacheMgr = new CacheManager(etlConfig);
                cacheMgr.Start();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error initializing cache manager: " + ex.Message + ", startup will NOT complete", LogLevel.Info);
                throw new Exception("CacheManager not initialized");
            }

            WintapLogger.Log.Append("init complete", LogLevel.Info);
        }

        private void FileWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            fileSensor = new FileSerializer(esperNameSpacePrefix + "file-activity.epl");
        }

        private void RegWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            regSensor = new RegistrySerializer(esperNameSpacePrefix + "reg-activity.epl");
        }

        #endregion
    }
}
