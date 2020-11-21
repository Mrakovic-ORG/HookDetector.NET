using System;
using System.Runtime.InteropServices;

namespace Hook_Detector
{
    internal static class Pinvoke
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        public static extern int NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")]
        public static extern int RtlCompareMemory(IntPtr Source1, IntPtr Source2, int Length);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress,
            IntPtr ZeroBits, IntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition,
            uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern uint NtOpenSection(out IntPtr sectionHandle, uint desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
    }
}