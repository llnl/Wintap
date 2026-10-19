using System;
using System.Collections.Generic;
using gov.llnl.wintap.platform.windows.infrastructure;
using Xunit;
namespace Wintap.Tests
{
 [Trait("Category", "fio-04")]
 public class WindowsFileVolumeMapTests
 {
  private sealed class Fake : WindowsFileVolumeMap.INative
  {
   internal string[] Volumes = { @"\\?\Volume{one}\", @"\\?\Volume{bare}\" };
   internal int Index, Closed, EndError = 18, QuerySize = 256, MountSize = 256, Largest;
   internal bool FirstFails, QueryFails, MountFails, OneVolumeFails, NextThrows;
   public IntPtr First(char[] b, out int e) { e = 5; if (FirstFails) return new IntPtr(-1); Copy(Volumes[0] + "\0", b); return new IntPtr(42); }
   public bool Next(IntPtr h, char[] b, out int e) { e = EndError; if (NextThrows) throw new Exception(); if (++Index >= Volumes.Length) return false; Copy(Volumes[Index] + "\0", b); return true; }
   public void Close(IntPtr h) { Closed++; }
   public int Query(string a, char[] b, out int e)
   {
    Largest = Math.Max(Largest, b.Length); e = 122;
    if (b.Length < QuerySize) return 0;
    if (QueryFails || (OneVolumeFails && a == "Volume{one}")) { e = 5; return 0; }
    string value = a == "Volume{one}" ? "\\Device\\Live\0\\Device\\Historical\0\0" :
     a == "Volume{bare}" ? "\\Device\\Bare\0\0" : a == "S:" ? "\\Device\\HarddiskVolumeShadowCopy20\0\0" :
     a == "X:" ? "\\??\\C:\\Subst\0\0" : a == "N:" ? "\\Device\\Mup\\server\\share\0\0" : null;
    if (value == null) { e = 2; return 0; } Copy(value, b); e = 0; return value.Length;
   }
   public bool Mounts(string v, char[] b, out int n, out int e)
   {
    Largest = Math.Max(Largest, b.Length); n = MountSize; e = 234;
    if (b.Length < MountSize) return false;
    if (MountFails) { e = 5; return false; }
    string value = v.Contains("one") ? "C:\\Archive\\\0D:\\Other\\\0\0" : "\0";
    Copy(value, b); n = value.Length; e = 0; return true;
   }
   private static void Copy(string s, char[] b) { s.CopyTo(0, b, 0, s.Length); }
  }
  [Fact] public void DiscoveryParsesCurrentTargetMountsAndDirectSnapshots()
  {
   var api = new Fake(); var map = WindowsFileVolumeMap.Discover(api);
   Assert.Equal(1, api.Closed);
   Assert.Equal(@"d:\other\file", WindowsFilePathNormalizer.Normalize(@"\Device\Live\FILE", map));
   Assert.Equal(@"\device\historical\file", WindowsFilePathNormalizer.Normalize(@"\Device\Historical\FILE", map));
   Assert.Equal(@"\device\bare\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{bare}\FILE", map));
   Assert.Equal(@"s:\file", WindowsFilePathNormalizer.Normalize(@"\Device\HarddiskVolumeShadowCopy20\FILE", map));
   Assert.Equal(@"\\server\share\file", WindowsFilePathNormalizer.Normalize(@"\Device\Mup\server\share\FILE", map));
  }
  [Theory] [InlineData(1024, 256)] [InlineData(256, 1024)] [InlineData(65536, 65536)]
  public void BuffersResize(int query, int mount)
  {
   var api = new Fake { QuerySize = query, MountSize = mount }; var map = WindowsFileVolumeMap.Discover(api);
   Assert.True(map.Count > 0); Assert.Equal(Math.Max(query, mount), api.Largest); Assert.Equal(1, api.Closed);
  }
  [Fact] public void CeilingAndEntryFailureNeverFabricateMaps()
  {
   var api = new Fake { QuerySize = 65537 }; Assert.Equal(0, WindowsFileVolumeMap.Discover(api).Count); Assert.Equal(65536, api.Largest);
   api = new Fake { MountSize = 65537 }; var map = WindowsFileVolumeMap.Discover(api);
   Assert.Equal(@"\device\live\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{one}\FILE", map));
   api = new Fake { QueryFails = true }; Assert.Equal(0, WindowsFileVolumeMap.Discover(api).Count); Assert.Equal(1, api.Closed);
   api = new Fake { MountFails = true }; map = WindowsFileVolumeMap.Discover(api);
   Assert.Equal(@"\device\live\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{one}\FILE", map));
  }
  [Fact] public void WholeEnumerationFailureIsEmptyAndClosesHandle()
  {
   var api = new Fake { EndError = 5 }; Assert.Equal(0, WindowsFileVolumeMap.Discover(api).Count); Assert.Equal(1, api.Closed);
   api = new Fake { FirstFails = true }; Assert.Equal(0, WindowsFileVolumeMap.Discover(api).Count); Assert.Equal(0, api.Closed);
  }
  [Fact] public void PerVolumeFailurePreservesOtherEntriesAndExceptionsCloseEnumeration()
  {
   var api = new Fake { OneVolumeFails = true }; var map = WindowsFileVolumeMap.Discover(api);
   Assert.Equal(@"\\?\volume{one}\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{one}\FILE", map));
   Assert.Equal(@"\device\bare\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{bare}\FILE", map));
   Assert.Equal(@"s:\file", WindowsFilePathNormalizer.Normalize(@"\Device\HarddiskVolumeShadowCopy20\FILE", map));
   api = new Fake { NextThrows = true }; Assert.Equal(0, WindowsFileVolumeMap.Discover(api).Count); Assert.Equal(1, api.Closed);
  }
  [Fact] public void ConflictingMountAssociationsAreOmitted()
  {
   var map = new WindowsFileVolumeMap(new[] {
    new WindowsFileVolumeMap.Entry(@"\\?\Volume{one}", @"\Device\One", new[] { @"D:\" }),
    new WindowsFileVolumeMap.Entry(@"\\?\Volume{two}", @"\Device\Two", new[] { @"D:\" }) });
   Assert.Equal(@"\device\one\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{one}\FILE", map));
   Assert.Equal(@"\device\two\file", WindowsFilePathNormalizer.Normalize(@"\Device\Two\FILE", map));
  }
  [Fact] public void AmbiguousAliasesAreOmittedAndInputArraysAreCopied()
  {
   var mounts = new[] { @"D:\" };
   var entries = new[] { new WindowsFileVolumeMap.Entry(@"\\?\Volume{conflict}", @"\Device\One", mounts), new WindowsFileVolumeMap.Entry(@"\\?\Volume{conflict}", @"\Device\Two", mounts), new WindowsFileVolumeMap.Entry("good", @"\Device\Good", new[] { @"E:\" }) };
   var map = new WindowsFileVolumeMap(entries); mounts[0] = @"Z:\";
   Assert.Equal(@"\\?\volume{conflict}\file", WindowsFilePathNormalizer.Normalize(@"\\?\Volume{conflict}\FILE", map));
   Assert.Equal(@"e:\file", WindowsFilePathNormalizer.Normalize(@"\Device\Good\FILE", map));
  }
 }
}
