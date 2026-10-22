using System.Runtime.InteropServices;

namespace SensEvents
{
    // ISensLogon from sens.h: preserve all seven methods in COM vtable order.
    [ComImport]
    [Guid("D597BAB3-5B9F-11D1-8DD2-00AA004ABD5E")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ISensLogon
    {
        void Logon([MarshalAs(UnmanagedType.BStr)] string userName);
        void Logoff([MarshalAs(UnmanagedType.BStr)] string userName);
        void StartShell([MarshalAs(UnmanagedType.BStr)] string userName);
        void DisplayLock([MarshalAs(UnmanagedType.BStr)] string userName);
        void DisplayUnlock([MarshalAs(UnmanagedType.BStr)] string userName);
        void StartScreenSaver([MarshalAs(UnmanagedType.BStr)] string userName);
        void StopScreenSaver([MarshalAs(UnmanagedType.BStr)] string userName);
    }
}
