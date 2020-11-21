using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Hook_Detector;

namespace Examples
{
    internal class Program
    {

        private static void Main()
        {
            Console.WriteLine($"HookDetector.NET Version: {HookDetector.Version}\n");
            Console.WriteLine("Executing Example1");
            Example1();

            Console.WriteLine("\nExecuting Example2");
            Example2();

            Console.ResetColor();
            Console.ReadKey();
        }

        private static void Example1()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"IsDebuggerPresent (not hooked) = {IsDebuggerPresent()}");
            var hookDetector = new HookDetector("kernel32.dll");
            var isHooked = hookDetector.IsHooked("IsDebuggerPresent");
            Console.WriteLine($"is Kernel32.IsDebuggerPresent hooked = {isHooked}");
            Console.ResetColor();
        }

        private static void Example2()
        {
            byte[] hook =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0(false)
                0xC3                            // ret
            };
            var addr = GetProcAddress(LoadLibrary("kernel32.dll"), "IsDebuggerPresent");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Hooking IsDebuggerPresent...");
            VirtualProtectEx(Process.GetCurrentProcess().Handle, addr, (UIntPtr)1, 0x40, out var oldp);
            WriteProcessMemory(Process.GetCurrentProcess().Handle, addr, hook, 6, out _);
            VirtualProtectEx(Process.GetCurrentProcess().Handle, addr, (UIntPtr)1, oldp, out _);

            Console.WriteLine($"IsDebuggerPresent (Hooked to be always false) = {IsDebuggerPresent()}");

            var hookDetector = new HookDetector("kernel32.dll");
            var isHooked = hookDetector.IsHooked("IsDebuggerPresent");
            Console.WriteLine($"is Kernel32.IsDebuggerPresent hooked = {isHooked}");
            Console.ResetColor();
        }

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
    }
}