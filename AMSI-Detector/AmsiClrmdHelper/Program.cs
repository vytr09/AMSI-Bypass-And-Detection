using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.Diagnostics.Runtime;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length != 1 || !int.TryParse(args[0], out int pid))
        {
            Console.WriteLine("Usage: AmsiClrmdHelper <pid>");
            return 2;
        }

        bool bypassDetected = false;
        string bypassReason = "";

        try
        {
            using (var dataTarget = DataTarget.AttachToProcess(pid, suspend: false))
            {
                var clr = dataTarget.ClrVersions[0].CreateRuntime();
                var heap = clr.Heap;

                // --- AMSI detection logic ---

                ClrType amsiType = null;

                // Try to find AmsiUtils type
                amsiType = clr.EnumerateModules()
                    .SelectMany(module => module.EnumerateTypeDefToMethodTableMap())
                    .Select(t => clr.GetTypeByMethodTable(t.MethodTable))
                    .FirstOrDefault(type => type?.Name == "System.Management.Automation.AmsiUtils");

                if (amsiType == null)
                {
                    foreach (var module in clr.EnumerateModules())
                    {
                        foreach (var typeMap in module.EnumerateTypeDefToMethodTableMap())
                        {
                            var type = clr.GetTypeByMethodTable(typeMap.MethodTable);
                            if (type?.Name == "System.Management.Automation.AmsiUtils")
                            {
                                amsiType = type;
                                break;
                            }
                        }
                        if (amsiType != null) break;
                    }
                }

                if (amsiType != null)
                {
                    // 1. Detect amsiInitFailed
                    var amsiInitFailed = amsiType.GetStaticFieldByName("amsiInitFailed");
                    if (amsiInitFailed != null)
                    {
                        foreach (var appDomain in clr.AppDomains)
                        {
                            try
                            {
                                bool value = amsiInitFailed.Read<bool>(appDomain);
                                if (value)
                                {
                                    bypassDetected = true;
                                    bypassReason += $"amsiInitFailed set to true in {appDomain.Name}\n";
                                }
                            }
                            catch { }
                        }
                    }

                    // 2. Detect amsiContext pointer zeroing/nulling
                    var amsiContext = amsiType.GetStaticFieldByName("amsiContext");
                    if (amsiContext != null)
                    {
                        foreach (var appDomain in clr.AppDomains)
                        {
                            try
                            {
                                ulong ptr = amsiContext.Read<ulong>(appDomain);
                                if (ptr == 0)
                                {
                                    bypassDetected = true;
                                    bypassReason += $"amsiContext is NULL in {appDomain.Name}\n";
                                }
                                else
                                {
                                    byte[] buffer = new byte[16];
                                    int bytesRead = clr.DataTarget.DataReader.Read(ptr, buffer);
                                    int ptrSize = IntPtr.Size;
                                    bool firstPtrZero = bytesRead > 0 && buffer.Take(ptrSize).All(b => b == 0);
                                    if (firstPtrZero)
                                    {
                                        bypassDetected = true;
                                        bypassReason += $"amsiContext first {ptrSize} bytes are zeroed in {appDomain.Name}\n";
                                    }
                                }
                            }
                            catch { }
                        }
                    }

                    // 3. Find ScanContent method and check for bypass
                    var expectedMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        "ToString", "Equals", "GetHashCode", "Finalize", ".cctor", ".ctor",
                        "GetProcessHostName", "Init", "ScanContent", "CurrentDomain_ProcessExit",
                        "CloseSession", "Uninitialize", "VerifyAmsiUninitializeCalled", "CheckAmsiInit"
                    };

                    ClrMethod scanContentMethod = !amsiType.Methods.IsDefault ? amsiType.Methods.FirstOrDefault(m => m.Name == "ScanContent") : null;
                    var suspiciousMethods = !amsiType.Methods.IsDefault
                        ? amsiType.Methods.Where(m => !expectedMethods.Contains(m.Name)).ToList()
                        : new List<ClrMethod>();

                    if (suspiciousMethods.Any())
                    {
                        foreach (var method in suspiciousMethods)
                        {
                            // Check if this method has simple return pattern (common in bypasses)
                            byte[] methodCode = new byte[32];
                            int bytesRead = clr.DataTarget.DataReader.Read(method.NativeCode, methodCode);
                            if (bytesRead > 0 && IsSimpleReturnPattern(methodCode, bytesRead))
                            {
                                bypassDetected = true;
                                bypassReason += $"Method '{method.Name}' found in AmsiUtils (TrollAMSI-style bypass)\n";
                            }
                        }
                    }

                    if (scanContentMethod != null)
                    {
                        ulong originalScanContentNativeCode = scanContentMethod.NativeCode;
                        byte[] scanContentCode = new byte[64];
                        int bytesRead = clr.DataTarget.DataReader.Read(originalScanContentNativeCode, scanContentCode);
                        if (bytesRead > 0 && IsSimpleReturnPattern(scanContentCode, bytesRead))
                        {
                            bypassDetected = true;
                            bypassReason += "ScanContent replaced with simple return pattern\n";
                        }
                    }
                    else
                    {
                        // If ScanContent is missing, but 'M' is present, flag as bypass
                        if (suspiciousMethods.Any(m => m.Name == "M"))
                        {
                            bypassDetected = true;
                            bypassReason += "ScanContent missing and method 'M' present in AmsiUtils (TrollAMSI-style bypass)\n";
                        }
                        else
                        {
                            bypassDetected = true;
                            bypassReason += "ScanContent method missing from AmsiUtils\n";
                        }
                    }
                }
                else
                {
                    bypassDetected = true;
                    bypassReason += "AmsiUtils type not found\n";
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("CLRMD error: " + ex.Message);
            return 2;
        }

        if (bypassDetected)
        {
            Console.WriteLine("[CLRMD] AMSI BYPASS DETECTED:");
            Console.WriteLine(bypassReason.Trim());
            return 1;
        }
        else
        {
            Console.WriteLine("[CLRMD] No AMSI bypass detected.");
            return 0;
        }
    }

    private static bool IsSimpleReturnPattern(byte[] code, int length)
    {
        if (length < 2) return false;

        // Pattern 1: mov eax, 1; ret (B8 01 00 00 00 C3)
        if (length >= 6 && code[0] == 0xB8 && code[1] == 0x01 && code[2] == 0x00 &&
            code[3] == 0x00 && code[4] == 0x00 && code[5] == 0xC3)
        {
            return true;
        }

        // Pattern 2: xor eax, eax; inc eax; ret (31 C0 40 C3 or 33 C0 40 C3)
        if (length >= 4 && ((code[0] == 0x31 && code[1] == 0xC0) || (code[0] == 0x33 && code[1] == 0xC0)) &&
            code[2] == 0x40 && code[3] == 0xC3)
        {
            return true;
        }

        // Pattern 3: mov eax, 1; ret in x64 (48 C7 C0 01 00 00 00 C3)
        if (length >= 8 && code[0] == 0x48 && code[1] == 0xC7 && code[2] == 0xC0 &&
            code[3] == 0x01 && code[4] == 0x00 && code[5] == 0x00 && code[6] == 0x00 && code[7] == 0xC3)
        {
            return true;
        }

        // Pattern 4: Simple return in x86 (B8 01 00 00 00 C3)
        if (length >= 6 && code[0] == 0xB8 && code[1] == 0x01 && code[2] == 0x00 &&
            code[3] == 0x00 && code[4] == 0x00 && code[5] == 0xC3)
        {
            return true;
        }

        // Pattern 5: Very short return patterns that are suspicious
        if (length <= 10)
        {
            for (int i = 0; i < Math.Min(4, length); i++)
            {
                if (code[i] == 0xC3) // ret instruction
                {
                    return true;
                }
            }
        }

        return false;
    }
}
