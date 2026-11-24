using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using gov.llnl.wintap.platform.windows.collect.etw;
using SensEvents;
using Xunit;
using Xunit.Abstractions;

namespace Wintap.Tests
{
    public class SensLogonContractTests
    {
        private static readonly string[] CallbackNames =
        {
            "Logon", "Logoff", "StartShell", "DisplayLock", "DisplayUnlock",
            "StartScreenSaver", "StopScreenSaver"
        };

        private readonly ITestOutputHelper output;

        public SensLogonContractTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        [Trait("Category", "sens-01")]
        public void ProductionInterface_HasOfficialDualMetadataContract()
        {
            AssertInterfaceContract();
        }

        [Fact]
        [Trait("Category", "sens-01")]
        public void SensSensor_RetainsExplicitComInterfaceWithoutConstruction()
        {
            Type sensorType = typeof(SensSensor);
            Assert.Contains(typeof(ISensLogon), sensorType.GetInterfaces());
            Assert.True(sensorType.GetCustomAttribute<ComVisibleAttribute>().Value);
            Assert.Equal(ClassInterfaceType.None,
                sensorType.GetCustomAttribute<ClassInterfaceAttribute>().Value);
        }

        [Fact]
        [Trait("Category", "sens-01")]
        public void NativeDualVtable_AllSevenSlotsDeliverExactlyOneCorrectCallback()
        {
            output.WriteLine($"OS: {RuntimeInformation.OSDescription}; OS architecture: {RuntimeInformation.OSArchitecture}");
            output.WriteLine($"Process architecture: {RuntimeInformation.ProcessArchitecture}; Runtime: {RuntimeInformation.FrameworkDescription}");
            output.WriteLine($"Production assembly: {typeof(ISensLogon).Assembly.Location}; MVID: {typeof(ISensLogon).Module.ModuleVersionId}");
            Assert.True(OperatingSystem.IsWindows() &&
                RuntimeInformation.OSArchitecture == Architecture.X64 &&
                RuntimeInformation.ProcessArchitecture == Architecture.X64 &&
                Environment.Version.Major == 10,
                "Native SENS contract test requires Windows x64, an x64 .NET 10 process and built-in COM interop.");

            // Reject an incorrect layout before reading any native callback slots.
            AssertInterfaceContract();
            var subscriber = new SensLogonRecordingSubscriber();
            IntPtr interfacePointer = IntPtr.Zero;
            try
            {
                interfacePointer = Marshal.GetComInterfaceForObject(subscriber, typeof(ISensLogon));
                Assert.NotEqual(IntPtr.Zero, interfacePointer);
                IntPtr vtable = Marshal.ReadIntPtr(interfacePointer);
                const string userName = "DOMAIN\\Zoë-用户-Δ";

                for (int index = 0; index < CallbackNames.Length; index++)
                {
                    int slot = 7 + index;
                    IntPtr callbackPointer = Marshal.ReadIntPtr(vtable, slot * IntPtr.Size);
                    var callback = Marshal.GetDelegateForFunctionPointer<NativeSensCallback>(callbackPointer);
                    IntPtr bstr = Marshal.StringToBSTR(userName);
                    try
                    {
                        int previousCount = subscriber.Calls.Count;
                        int hresult = callback(interfacePointer, bstr);
                        Assert.Equal(0, hresult); // S_OK
                        Assert.Equal(previousCount + 1, subscriber.Calls.Count);
                        Assert.Equal((CallbackNames[index], userName), subscriber.Calls[index]);
                        output.WriteLine($"Slot {slot}: {CallbackNames[index]}, S_OK, username unchanged, exactly one call.");
                    }
                    finally
                    {
                        Marshal.FreeBSTR(bstr);
                    }
                }

                Assert.Equal(CallbackNames.Length, subscriber.Calls.Count);
            }
            finally
            {
                if (interfacePointer != IntPtr.Zero)
                {
                    Marshal.Release(interfacePointer);
                }
                GC.KeepAlive(subscriber);
            }
        }

        private static void AssertInterfaceContract()
        {
            Type interfaceType = typeof(ISensLogon);
            Assert.Equal(typeof(SensSensor).Assembly, interfaceType.Assembly);
            Assert.True(interfaceType.IsInterface);
            Assert.Equal(new Guid("D597BAB3-5B9F-11D1-8DD2-00AA004ABD5E"), interfaceType.GUID);
            Assert.True(interfaceType.IsImport);
            Assert.NotNull(interfaceType.GetCustomAttribute<ComImportAttribute>());
            Assert.Equal(ComInterfaceType.InterfaceIsDual,
                interfaceType.GetCustomAttribute<InterfaceTypeAttribute>().Value);

            MethodInfo[] methods = interfaceType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .OrderBy(method => method.MetadataToken).ToArray();
            Assert.Equal(CallbackNames, methods.Select(method => method.Name).ToArray());
            for (int index = 0; index < methods.Length; index++)
            {
                MethodInfo method = methods[index];
                Assert.Equal(index + 1, method.GetCustomAttribute<DispIdAttribute>().Value);
                Assert.Equal(typeof(void), method.ReturnType);
                Assert.Null(method.GetCustomAttribute<PreserveSigAttribute>());
                Assert.Equal((MethodImplAttributes)0, method.GetMethodImplementationFlags() & MethodImplAttributes.PreserveSig);
                ParameterInfo parameter = Assert.Single(method.GetParameters());
                Assert.Equal(typeof(string), parameter.ParameterType);
                Assert.Equal(UnmanagedType.BStr, parameter.GetCustomAttribute<MarshalAsAttribute>().Value);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NativeSensCallback(IntPtr interfacePointer, IntPtr userNameBstr);
    }

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    public class SensLogonRecordingSubscriber : ISensLogon
    {
        public List<(string MethodName, string UserName)> Calls { get; } = new List<(string, string)>();

        public void Logon(string userName) => Calls.Add((nameof(Logon), userName));
        public void Logoff(string userName) => Calls.Add((nameof(Logoff), userName));
        public void StartShell(string userName) => Calls.Add((nameof(StartShell), userName));
        public void DisplayLock(string userName) => Calls.Add((nameof(DisplayLock), userName));
        public void DisplayUnlock(string userName) => Calls.Add((nameof(DisplayUnlock), userName));
        public void StartScreenSaver(string userName) => Calls.Add((nameof(StartScreenSaver), userName));
        public void StopScreenSaver(string userName) => Calls.Add((nameof(StopScreenSaver), userName));
    }
}
