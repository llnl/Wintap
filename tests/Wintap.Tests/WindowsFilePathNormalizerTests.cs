using System;
using System.Globalization;
using System.Threading.Tasks;
using gov.llnl.wintap.platform.windows.infrastructure;
using Xunit;
namespace Wintap.Tests
{
 [Trait("Category", "fio-04")]
 public class WindowsFilePathNormalizerTests
 {
  internal static WindowsFileVolumeMap Map => new WindowsFileVolumeMap(new[] {
   new WindowsFileVolumeMap.Entry(@"\\?\Volume{known}", @"\Device\HarddiskVolume12", new[] { @"D:\", @"C:\Other\" }),
   new WindowsFileVolumeMap.Entry(@"\??\Volume{known}", @"\Device\HarddiskVolume12", new[] { @"D:\" }),
   new WindowsFileVolumeMap.Entry(@"\\?\Volume{bare}", @"\Device\Bare", Array.Empty<string>()),
   new WindowsFileVolumeMap.Entry("snapshot", @"\Device\HarddiskVolumeShadowCopy21", new[] { @"S:\" }),
   new WindowsFileVolumeMap.Entry("directory", @"\Device\Mounted", new[] { @"C:\Archive\" }) });
  [Theory]
  [InlineData(@"C:\Folder\FILE", @"c:\folder\file")]
  [InlineData(@"\\server\share\FILE", @"\\server\share\file")]
  [InlineData(@"\\?\C:\FILE", @"c:\file")]
  [InlineData(@"\??\C:\FILE", @"c:\file")]
  [InlineData(@"\\?\UNC\server\share\FILE", @"\\server\share\file")]
  [InlineData(@"\??\UNC\server\share\FILE", @"\\server\share\file")]
  [InlineData(@"\DEVICE\HarddiskVolume12\FILE:Stream", @"d:\file:stream")]
  [InlineData(@"\Device\Mounted\FILE", @"c:\archive\file")]
  [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy139\$Mft", @"\device\harddiskvolumeshadowcopy139\$mft")]
  [InlineData(@"\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy20\$Mft", @"\device\harddiskvolumeshadowcopy20\$mft")]
  [InlineData(@"\Device\HarddiskVolumeShadowCopy20\$Mft", @"\device\harddiskvolumeshadowcopy20\$mft")]
  [InlineData(@"\Device\HarddiskVolumeShadowCopy21\$Mft", @"s:\$mft")]
  [InlineData(@"\\?\Volume{known}\FILE", @"d:\file")]
  [InlineData(@"\??\Volume{known}\FILE", @"d:\file")]
  [InlineData(@"\\?\Volume{bare}\FILE", @"\device\bare\file")]
  [InlineData(@"\Device\Mup\server\share\FILE", @"\\server\share\file")]
  [InlineData(@"\Device\LanmanRedirector\server\share\FILE", @"\\server\share\file")]
  [InlineData(@"\Device\HarddiskVolume12\Device\HarddiskVolume12\FILE", @"d:\device\harddiskvolume12\file")]
  [InlineData(@"\Device\HarddiskVolume12", @"d:\")]
  [InlineData(@"\Device\HarddiskVolume12\\FILE", @"d:\\file")]
  [InlineData(null, null)] [InlineData("", "")]
  public void Matrix(string input, string expected) => Check(input, expected);
  private static void Check(string input, string expected)
  {
   var old = CultureInfo.CurrentCulture;
   try { foreach (string culture in new[] { "en-US", "tr-TR" }) {
    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
    string actual = WindowsFilePathNormalizer.Normalize(input, Map);
    Assert.Equal(expected, actual); Assert.Equal(actual, WindowsFilePathNormalizer.Normalize(actual, Map));
   }} finally { CultureInfo.CurrentCulture = old; }
  }
  [Theory]
  [InlineData(@"\Device\HarddiskVolume1\FILE")]
  [InlineData(@"\Device\HarddiskVolume1x\FILE")]
  [InlineData(@"\Device\HarddiskVolume123\FILE")]
  [InlineData(@"\Device\HarddiskVolumeShadowCopy1\FILE")]
  [InlineData(@"\\?\Volume{unknown}\FILE")]
  [InlineData(@"C:relative.txt")]
  [InlineData("Relative")]
  [InlineData(@"\Device\Mup\;LanmanRedirector\server\share\FILE")]
  [InlineData(@"\Device\LanmanRedirector\;X:123\server\share\FILE")]
  [InlineData(@"\\?\UNC\\share\FILE")]
  [InlineData(@"\\?\UNC\server\\FILE")]
  [InlineData(@"\\?\unknown\FILE")]
  public void UnknownsRetainStructure(string path) => Check(path, path.ToLowerInvariant());
  [Theory]
  [InlineData(".")] [InlineData("..")] [InlineData("Tail.")] [InlineData("Tail ")]
  [InlineData("CON.txt")] [InlineData("LPT1:stream")] [InlineData("COM\u00b9.txt")] [InlineData("NUL")]
  public void UnsafeComponentsRetainNativeSemantics(string component)
  {
   Check(@"\\?\C:\" + component, (@"\\?\C:\" + component).ToLowerInvariant());
   Check(@"\\?\UNC\server\share\" + component, (@"\\?\UNC\server\share\" + component).ToLowerInvariant());
   Check(@"\Device\HarddiskVolume12\" + component, (@"\Device\HarddiskVolume12\" + component).ToLowerInvariant());
   Check(@"\\?\Volume{known}\" + component, (@"\Device\HarddiskVolume12\" + component).ToLowerInvariant());
  }
  [Fact] public void SafetyPrecedesRanking()
  {
   foreach (var mounts in new[] { new[] { @"C:\Bad.\", @"Z:\Safe\", @"D:\Longer\" }, new[] { @"D:\Longer\", @"Z:\Safe\", @"C:\Bad.\" } }) {
    var map = new WindowsFileVolumeMap(new[] { new WindowsFileVolumeMap.Entry("alias", @"\Device\Test", mounts) });
    Assert.Equal(@"z:\safe\file", WindowsFilePathNormalizer.Normalize(@"\Device\Test\FILE", map));
   }
  }
  [Fact] public void LeaseSingleFlightRemovalAndExpiredPublication()
  {
   double now = 0; int calls = 0; Action work = null; int queued = 0; var next = Map;
   var n = new WindowsFilePathNormalizer(() => { calls++; return next; }, () => now, a => { queued++; work = a; }, _ => throw new Exception());
   Assert.Equal(0, calls); n.Initialize(); Assert.Equal(@"d:\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
   now = 60;
   Parallel.For(0, 100, _ => Assert.Equal(@"\device\harddiskvolume12\file", n.Normalize(@"\Device\HarddiskVolume12\FILE")));
   Assert.Equal(1, queued); Assert.Equal(1, calls); next = WindowsFileVolumeMap.Empty; work();
   Assert.Equal(@"\device\harddiskvolume12\file", n.Normalize(@"\Device\HarddiskVolume12\FILE")); Assert.Equal(1, queued);
   now = 120; n.Normalize(@"C:\FILE"); next = Map; work(); Assert.Equal(@"d:\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
   now = 180; n.Normalize(@"C:\FILE"); now = 240; work();
   Assert.Equal(@"\device\harddiskvolume12\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
  }
  [Fact] public void RankingUsesDirectDriveThenLengthThenLexicalOrder()
  {
   var map = new WindowsFileVolumeMap(new[] { new WindowsFileVolumeMap.Entry("alias", @"\Device\Test", new[] { @"Z:\", @"B:\", @"A:\Short\" }) });
   Assert.Equal(@"b:\file", WindowsFilePathNormalizer.Normalize(@"\Device\Test\FILE", map));
   map = new WindowsFileVolumeMap(new[] { new WindowsFileVolumeMap.Entry("alias", @"\Device\Test", new[] { @"Z:\Same\", @"B:\Same\" }) });
   Assert.Equal(@"b:\same\file", WindowsFilePathNormalizer.Normalize(@"\Device\Test\FILE", map));
   map = new WindowsFileVolumeMap(new[] { new WindowsFileVolumeMap.Entry("alias", @"\Device\Test", new[] { @"C:\Bad.\" }) });
   Assert.Equal(@"\device\test\file", WindowsFilePathNormalizer.Normalize(@"\Device\Test\FILE", map));
  }
  [Fact] public void RefreshRemapsAtomicallyAndDoesNotPublishAnExpiredLeaseAsFresh()
  {
   double now = 0; Action work = null; int calls = 0;
   var changed = new WindowsFileVolumeMap(new[] { new WindowsFileVolumeMap.Entry("alias", @"\Device\HarddiskVolume12", new[] { @"E:\" }) });
   WindowsFilePathNormalizer n = null;
   n = new WindowsFilePathNormalizer(() => {
    calls++;
    if (calls == 1) return Map;
    Assert.Equal(@"\device\harddiskvolume12\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
    return changed;
   }, () => now, a => work = a);
   n.Initialize(); now = 60; n.Normalize("relative"); work();
   Assert.Equal(@"e:\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
   now = 120; n.Normalize("relative"); now = 180; work();
   Assert.Equal(@"\device\harddiskvolume12\file", n.Normalize(@"\Device\HarddiskVolume12\FILE"));
  }
  [Fact] public void FailureIsThrottled()
  {
   double now = 0; int calls = 0; Action work = null;
   var n = new WindowsFilePathNormalizer(() => { calls++; throw new Exception(); }, () => now, a => work = a);
   n.Initialize(); Assert.Equal(@"c:\file", n.Normalize(@"\\?\C:\FILE")); Assert.Equal(1, calls);
   now = 60; n.Normalize("unknown"); Assert.Equal(1, calls); work(); n.Normalize("unknown"); Assert.Equal(2, calls);
  }
 }
}
