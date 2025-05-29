#ifndef MPOAV_PATCH_DETECTOR_H
#define MPOAV_PATCH_DETECTOR_H

#include <windows.h>

namespace detectors {
    class MpOavPatchDetector {
    public:
        MpOavPatchDetector();
        ~MpOavPatchDetector();

        /**
         * Checks if MpOav.dll's DllGetClassObject function is patched in the specified process
         * @param pid Process ID to check
         * @return true if patch is detected, false otherwise
         */
        bool isMpOavPatchedInProcess(DWORD pid);

    private:
        /**
         * Gets the base address of a module in a remote process
         * @param hProcess Handle to the target process
         * @param moduleName Name of the module to find
         * @return Base address of the module, or nullptr if not found
         */
        HMODULE getModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName);

        /**
         * Gets the remote address of a function by parsing PE export table
         * @param hProcess Handle to the target process
         * @param remoteModuleBase Base address of the remote module
         * @param functionName Name of the function to locate
         * @return Remote address of the function, or 0 if not found
         */
        DWORD_PTR getRemoteFunctionAddressByPE(HANDLE hProcess, HMODULE remoteModuleBase, const char* functionName);
    };
}

#endif // MPOAV_PATCH_DETECTOR_H