using System;
using System.Runtime.InteropServices;
using static Hook_Detector.Pinvoke;

namespace Hook_Detector
{
    public class HookDetector
    {
        public HookDetector(string moduleName, bool is32Bits = true)
        {
            this.ModuleName = moduleName;
            this.Is32Bits = is32Bits;
            Module = LoadLibrary(this.ModuleName);
            ModuleMapped = RemapNtModule();
        }

        private string ModuleName { get; }
        private bool Is32Bits { get; }
        private IntPtr Module { get; }
        private IntPtr ModuleMapped { get; }

        public bool IsHooked(string functionName)
        {
            var fnProcAddress = GetProcAddress(Module, functionName);
            if (fnProcAddress == IntPtr.Zero)
                throw new Exception($"Failed to get address of {nameof(fnProcAddress)}");

            var originalFnProcAddress = GetMappedProcAddress(ModuleMapped, functionName);
            if (fnProcAddress == IntPtr.Zero)
                throw new Exception($"Failed to get address of {nameof(originalFnProcAddress)}");

            var result = RtlCompareMemory(fnProcAddress, originalFnProcAddress, 24);
            return result != 24;
        }

        private unsafe IntPtr RemapNtModule()
        {
            var baseAddress = IntPtr.Zero;
            var uni = new UNICODE_STRING();
            if (Is32Bits)
                RtlInitUnicodeString(ref uni, $"\\KnownDlls32\\{ModuleName}");
            else
                RtlInitUnicodeString(ref uni, $"\\KnownDlls\\{ModuleName}");

            var objAttribute = new OBJECT_ATTRIBUTES
            {
                Length = sizeof(OBJECT_ATTRIBUTES),
                ObjectName = &uni,
                Attributes = 0x00000040
            };

            NtOpenSection(out var handler, 0x04, ref objAttribute);

            NtMapViewOfSection(handler, (IntPtr) (-1), ref baseAddress, IntPtr.Zero, IntPtr.Zero, out _, out _, 1, 0,
                0x02);
            NtClose(handler);
            return baseAddress;
        }

        private unsafe IntPtr GetMappedProcAddress(IntPtr moduleBaseAddress, string desiredFunction)
        {
            var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(moduleBaseAddress);
            IMAGE_EXPORT_DIRECTORY exportDirectory;

            if (!dosHeader.isValid)
                return IntPtr.Zero;

            var nt32 = Marshal.PtrToStructure<IMAGE_NT_HEADERS32>(moduleBaseAddress + dosHeader.e_lfanew);
            var nt64 = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(moduleBaseAddress + dosHeader.e_lfanew);

            if (nt32.Signature.Length != 4)
                return IntPtr.Zero;

            if (nt32.OptionalHeader.Magic != MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                exportDirectory = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(moduleBaseAddress +
                    (int) nt32.OptionalHeader.DataDirectory[0].VirtualAddress);
            else
                exportDirectory = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(moduleBaseAddress +
                    (int) nt64.OptionalHeader.DataDirectory[0].VirtualAddress);

            var functionTable = (uint*) (moduleBaseAddress + (int) exportDirectory.AddressOfFunctions);
            var nameTable = (uint*) (moduleBaseAddress + (int) exportDirectory.AddressOfNames);
            var ordinalTable = (ushort*) (moduleBaseAddress + (int) exportDirectory.AddressOfNameOrdinals);
            for (int i = 0, numberOfNames = (int) exportDirectory.NumberOfNames; i < numberOfNames; ++i)
            {
                var functionName = Marshal.PtrToStringAnsi(moduleBaseAddress + (int) nameTable[i]);
                if (functionName == desiredFunction)
                    return moduleBaseAddress + (int) functionTable[ordinalTable[i]];
            }

            return IntPtr.Zero;
        }
    }
}