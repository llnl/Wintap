using System.Runtime.InteropServices;

namespace SensEvents
{
    // The official dual interface has three IUnknown and four IDispatch slots
    // before these seven callbacks in COM vtable order.
    [ComImport]
    [Guid("D597BAB3-5B9F-11D1-8DD2-00AA004ABD5E")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface ISensLogon
    {
        [DispId(1)]
        void Logon([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(2)]
        void Logoff([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(3)]
        void StartShell([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(4)]
        void DisplayLock([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(5)]
        void DisplayUnlock([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(6)]
        void StartScreenSaver([MarshalAs(UnmanagedType.BStr)] string userName);
        [DispId(7)]
        void StopScreenSaver([MarshalAs(UnmanagedType.BStr)] string userName);
    }
}
