using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.model;
using Newtonsoft.Json;
using Xunit;

namespace Wintap.Tests
{
    public class SerializerScheduleTests
    {
        [Theory]
        [InlineData(10000, 5000)]
        [InlineData(1000, 500)]
        public void MemorySnapshotsDrainBeforeQueueCapacity(int capacity, int threshold)
        {
            var config = new ETLConfig { SerializationIntervalSec = 60 };
            var options = SerializerSchedule.ResolveOptions(config, "defaultserializer", capacity);
            Assert.True(options.UseDedicatedWorker);
            Assert.Equal(capacity, options.MaxQueueEvents);
            Assert.Equal(threshold, options.HighWaterEvents);
            Assert.Equal(60, options.IntervalSec);

            config.Serializers["defaultserializer"] = new ETLConfig.SerializerOptions {
                UseDedicatedWorker = false, HighWaterEvents = 0
            };
            options = SerializerSchedule.ResolveOptions(config, "defaultserializer", capacity);
            Assert.False(options.UseDedicatedWorker);
            Assert.Equal(0, options.HighWaterEvents);
        }

        [Fact]
        public void AnySerializerCanSelectWorkerAndBoundedSchedule()
        {
            var config = JsonConvert.DeserializeObject<ETLConfig>(@"{
                'SerializationIntervalSec': 60,
                'Serializers': { 'TcpConnectionSerializer': {
                    'UseDedicatedWorker': true, 'IntervalSec': 2,
                    'HighWaterEvents': 900, 'MaxQueueEvents': 1000
                }}
            }");
            var options = SerializerSchedule.ResolveOptions(config, "tcpconnectionserializer", 10000);
            Assert.True(options.UseDedicatedWorker);
            Assert.Equal(2, options.IntervalSec);
            Assert.Equal(1000, options.MaxQueueEvents);
            Assert.Equal(500, options.HighWaterEvents);
            var overridden = SerializerSchedule.ResolveOptions(config, "tcpconnectionserializer", 10000, 4000);
            Assert.Equal(4000, overridden.MaxQueueEvents);
            Assert.Equal(900, overridden.HighWaterEvents);

            Assert.True(SerializerSchedule.ShouldRequestHighWaterFlush("tcpconnectionserializer", 500, options.HighWaterEvents.Value, configured: true));
            Assert.False(SerializerSchedule.ShouldRequestHighWaterFlush("tcpconnectionserializer", 499, options.HighWaterEvents.Value, configured: true));
        }

        [Fact]
        public void LegacyDefaultsAndExplicitDisableArePreserved()
        {
            var config = new ETLConfig { SerializationIntervalSec = 60 };
            Assert.True(SerializerSchedule.ResolveOptions(config, "registryserializer", 10000).UseDedicatedWorker);
            Assert.False(SerializerSchedule.ResolveOptions(config, "fileserializer", 10000).UseDedicatedWorker);
            Assert.Equal(0, SerializerSchedule.ResolveOptions(config, "tcpconnectionserializer", 10000).HighWaterEvents);
            config.Serializers["registryserializer"] = new ETLConfig.SerializerOptions {
                UseDedicatedWorker = false, IntervalSec = 0, HighWaterEvents = 0, MaxQueueEvents = -1
            };
            var options = SerializerSchedule.ResolveOptions(config, "registryserializer", 10000);
            Assert.False(options.UseDedicatedWorker);
            Assert.Equal(60, options.IntervalSec);
            Assert.Equal(0, options.HighWaterEvents);
            Assert.Equal(10000, options.MaxQueueEvents);
        }

        [Theory]
        [InlineData("fileserializer", 60, 5, 5)]
        [InlineData("processserializer", 60, 5, 60)]
        [InlineData("fileserializer", 60, 0, 60)]
        [InlineData("fileserializer", 0, 0, 60)]
        [InlineData("registryserializer", 60, 5, 5)]
        public void ResolveIntervalSeconds_OverridesSupportedSerializers(
            string serializerName,
            int defaultIntervalSeconds,
            int fileIntervalSeconds,
            int expectedIntervalSeconds)
        {
            Assert.Equal(
                expectedIntervalSeconds,
                SerializerSchedule.ResolveIntervalSeconds(serializerName, defaultIntervalSeconds, fileIntervalSeconds));
        }

        [Theory]
        [InlineData("fileserializer", 4999, 5000, false)]
        [InlineData("fileserializer", 5000, 5000, true)]
        [InlineData("processserializer", 10000, 5000, false)]
        [InlineData("fileserializer", 10000, 0, false)]
        [InlineData("registryserializer", 4999, 5000, false)]
        [InlineData("registryserializer", 5000, 5000, true)]
        [InlineData("registryserializer", 10000, 0, false)]
        public void ShouldRequestHighWaterFlush_TriggersSupportedSerializersAtThreshold(
            string serializerName,
            long queueDepth,
            int highWaterEvents,
            bool expected)
        {
            Assert.Equal(expected, SerializerSchedule.ShouldRequestHighWaterFlush(serializerName, queueDepth, highWaterEvents));
        }

        [Theory]
        [InlineData(5000, 10000, 5000)]
        [InlineData(20000, 10000, 5000)]
        [InlineData(5000, 1000, 500)]
        [InlineData(5000, 1, 1)]
        [InlineData(5000, 0, 5000)]
        [InlineData(0, 10000, 0)]
        public void RegistryThreshold_ReservesQueueHeadroom(int configured, int capacity, int expected)
        {
            Assert.Equal(expected, SerializerSchedule.ResolveHighWaterEvents(configured, capacity));
        }

        [Theory]
        [InlineData(null, 10000, 10000)]
        [InlineData(0, 10000, 10000)]
        [InlineData(-1, 10000, 10000)]
        [InlineData(50000, 10000, 50000)]
        public void RegistryQueueCapacity_OnlyPositiveOverrideReplacesInheritedLimit(int? configured, int inherited, int expected)
        {
            Assert.Equal(expected, SerializerSchedule.ResolveQueueCapacity(configured, inherited));
        }

        [Fact]
        public void RegistrySchedule_MissingUsesDefaultsAndExplicitZeroFallsBack()
        {
            ETLConfig missing = JsonConvert.DeserializeObject<ETLConfig>("{}");
            ETLConfig disabled = JsonConvert.DeserializeObject<ETLConfig>(
                "{\"RegistrySerializationIntervalSec\":0,\"RegistrySerializationHighWaterEvents\":0}");
            Assert.Null(missing.RegistrySerializationIntervalSec);
            Assert.Null(missing.RegistrySerializationHighWaterEvents);
            Assert.Equal(5, SerializerSchedule.ResolveIntervalSeconds("registryserializer", 60, 5, missing.RegistrySerializationIntervalSec ?? 5));
            Assert.Equal(60, SerializerSchedule.ResolveIntervalSeconds("registryserializer", 60, 5, disabled.RegistrySerializationIntervalSec.Value));
            Assert.Equal(0, disabled.RegistrySerializationHighWaterEvents);
            Assert.Equal(2, SerializerSchedule.ResolveIntervalSeconds("registryserializer", 60, 5, 2));
        }

        [Fact]
        public void FileScheduleConfiguration_DistinguishesMissingFromExplicitZero()
        {
            ETLConfig missing = JsonConvert.DeserializeObject<ETLConfig>("{}");
            ETLConfig disabled = JsonConvert.DeserializeObject<ETLConfig>(
                "{\"FileSerializationIntervalSec\":0,\"FileSerializationHighWaterEvents\":0}");

            Assert.Null(missing.FileSerializationIntervalSec);
            Assert.Null(missing.FileSerializationHighWaterEvents);
            Assert.Equal(0, disabled.FileSerializationIntervalSec);
            Assert.Equal(0, disabled.FileSerializationHighWaterEvents);
        }
    }
}
