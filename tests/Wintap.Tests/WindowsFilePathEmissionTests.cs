using System;
using gov.llnl.wintap.platform.windows.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using System.Globalization;
using Xunit;
namespace Wintap.Tests
{
 [Trait("Category", "fio-04")]
 public class WindowsFilePathEmissionTests
 {
  [Theory]
  [InlineData(WintapMessage.ActivityTypeEnum.Read)]
  [InlineData(WintapMessage.ActivityTypeEnum.Write)]
  [InlineData(WintapMessage.ActivityTypeEnum.Delete)]
  public void ProductionFactoryPreservesMetadata(WintapMessage.ActivityTypeEnum activity)
  {
   var time = new DateTime(2026, 10, 12, 12, 0, 0, DateTimeKind.Utc); int calls = 0;
   var message = FileSensor.CreateFileMessage(@"\Device\HarddiskVolume12\FILE", 123, time, activity, 42, "activity", "correlation",
    p => { calls++; return WindowsFilePathNormalizer.Normalize(p, WindowsFilePathNormalizerTests.Map); });
   Assert.Equal(1, calls); Assert.Equal(@"d:\file", message.File.Path); Assert.Equal(123, message.PID);
   Assert.Equal(time.ToFileTimeUtc(), message.EventTime); Assert.Equal(42, message.File.BytesRequested);
   Assert.Equal(activity, message.ActivityType); Assert.Equal("activity", message.ActivityId); Assert.Equal("correlation", message.CorrelationId);
  }
  [Theory] [InlineData(null)] [InlineData("")] [InlineData(@"C:\trace.ETL")]
  public void FilteringPrecedesConversion(string path)
  {
   Assert.Null(FileSensor.CreateFileMessage(path, 1, DateTime.UtcNow, WintapMessage.ActivityTypeEnum.Write, 0, null, null, _ => throw new Exception()));
  }
  [Fact] public void SerializerKeepsWindowsValueAndExistingOtherPlatformBehavior()
  {
   var old = CultureInfo.CurrentCulture;
   try { foreach (string culture in new[] { "en-US", "tr-TR" }) {
    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
    foreach (string path in new[] { @"c:\file", @"\device\harddiskvolumeshadowcopy20\$mft", @"c:\I" }) {
     Assert.Same(path, FileSerializer.SelectPath(path, true)); Assert.Equal(path.ToLower(), FileSerializer.SelectPath(path, false));
    }
   }} finally { CultureInfo.CurrentCulture = old; }
  }
 }
}
