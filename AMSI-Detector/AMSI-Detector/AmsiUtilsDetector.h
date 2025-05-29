#ifndef AMSI_UTILS_DETECTOR_H
#define AMSI_UTILS_DETECTOR_H

#include <windows.h>
#include <vector>
#include <string>

namespace detectors {
    class AmsiUtilsDetector {
    public:
        AmsiUtilsDetector();
        ~AmsiUtilsDetector();

        /**
         * Checks if AMSI has been bypassed using AmsiUtils field manipulation in the specified process
         * @param pid Process ID to check
         * @return true if bypass is detected, false otherwise
         */
        bool isAmsiUtilsBypassedInProcess(DWORD pid);

    private:
        /**
         * Searches for .NET assembly in process memory
         * @param hProcess Handle to the target process
         * @param assemblyName Name of the assembly to find (e.g., "System.Management.Automation")
         * @return Base address of the assembly, or 0 if not found
         */
        DWORD_PTR findDotNetAssembly(HANDLE hProcess, const std::string& assemblyName);

        /**
         * Searches for AmsiUtils class in System.Management.Automation assembly
         * @param hProcess Handle to the target process
         * @param assemblyBase Base address of the assembly
         * @return Address of AmsiUtils class metadata, or 0 if not found
         */
        DWORD_PTR findAmsiUtilsClass(HANDLE hProcess, DWORD_PTR assemblyBase);

        /**
         * Checks if amsiInitFailed field has been set to true
         * @param hProcess Handle to the target process
         * @param amsiUtilsAddr Address of AmsiUtils class
         * @return true if bypass detected, false otherwise
         */
        bool checkAmsiInitFailedBypass(HANDLE hProcess, DWORD_PTR amsiUtilsAddr);

        /**
         * Checks if amsiContext has been corrupted/zeroed
         * @param hProcess Handle to the target process
         * @param amsiUtilsAddr Address of AmsiUtils class
         * @return true if bypass detected, false otherwise
         */
        bool checkAmsiContextBypass(HANDLE hProcess, DWORD_PTR amsiUtilsAddr);

        /**
         * Searches for specific field in AmsiUtils class
         * @param hProcess Handle to the target process
         * @param classAddr Address of the class
         * @param fieldName Name of the field to find
         * @return Address of the field, or 0 if not found
         */
        DWORD_PTR findFieldInClass(HANDLE hProcess, DWORD_PTR classAddr, const std::string& fieldName);

        /**
         * Searches memory regions for .NET CLR patterns
         * @param hProcess Handle to the target process
         * @return Vector of potential CLR heap addresses
         */
        std::vector<DWORD_PTR> findCLRHeapRegions(HANDLE hProcess);

        /**
         * Scans memory region for AmsiUtils type signatures
         * @param hProcess Handle to the target process
         * @param baseAddr Base address to start scanning
         * @param size Size of region to scan
         * @return Address of AmsiUtils if found, 0 otherwise
         */
        DWORD_PTR scanForAmsiUtilsSignature(HANDLE hProcess, DWORD_PTR baseAddr, SIZE_T size);
    };
}

#endif // AMSI_UTILS_DETECTOR_H