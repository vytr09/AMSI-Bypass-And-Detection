using System;
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

        try
        {
            // Updated to remove the undefined 'AttachFlag' and use the correct overload of AttachToProcess
            using (var dataTarget = DataTarget.AttachToProcess(pid, suspend: false))
            {
                var clr = dataTarget.ClrVersions[0].CreateRuntime();
                var heap = clr.Heap;

                var amsiType = heap.GetTypeByName("System.Management.Automation.AmsiUtils");
                if (amsiType != null)
                {
                    var amsiInitFailed = amsiType.GetStaticFieldByName("amsiInitFailed");
                    if (amsiInitFailed != null)
                    {
                        foreach (var appDomain in clr.AppDomains)
                        {
                            bool value = amsiInitFailed.Read<bool>(appDomain);
                            Console.WriteLine($"amsiInitFailed={value} in {appDomain.Name}");
                            if (value)
                                return 1; // Bypass detected
                        }

                    }

                    var amsiContext = amsiType.GetStaticFieldByName("amsiContext");
                    if (amsiContext != null)
                    {
                        foreach (var appDomain in clr.AppDomains)
                        {
                            ulong ptr = amsiContext.Read<ulong>(appDomain);
                            Console.WriteLine($"amsiContext=0x{ptr:X} in {appDomain.Name}");
                            if (ptr == 0)
                            {
                                Console.WriteLine($"amsiContext=null in {appDomain.Name}");
                                return 1; // Bypass detected
                            }
                            else
                            {
                                // Try to read 16 bytes at the pointer
                                byte[] buffer = new byte[16];
                                int bytesRead = clr.DataTarget.DataReader.Read(ptr, buffer);
                                if (bytesRead > 0)
                                {
                                    Console.WriteLine($"amsiContext memory: {BitConverter.ToString(buffer, 0, bytesRead)}");
                                    int ptrSize = IntPtr.Size; // 8 for x64, 4 for x86
                                    bool firstPtrZero = buffer.Take(ptrSize).All(b => b == 0);
                                    if (firstPtrZero)
                                    {
                                        Console.WriteLine($"amsiContext first {ptrSize} bytes are zeroed in {appDomain.Name}");
                                        return 1; // Bypass detected
                                    }
                                }

                                else
                                {
                                    Console.WriteLine($"amsiContext: could not read memory at 0x{ptr:X} in {appDomain.Name}");
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("AmsiUtils type not found.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("CLRMD error: " + ex.Message);
            return 2;
        }

        return 0; // No bypass detected
    }
}
