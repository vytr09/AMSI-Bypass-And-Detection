#include "MpOavPatchDetector.h"
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

using namespace detectors;

MpOavPatchDetector::MpOavPatchDetector() {
    // Constructor implementation
}

MpOavPatchDetector::~MpOavPatchDetector() {
    // Destructor implementation
}

bool MpOavPatchDetector::isMpOavPatchedInProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[!] Failed to open process: " << pid << L" (Error: " << GetLastError() << L")" << std::endl;
        return false;
    }

    // Find MpOav.dll in the target process
    HMODULE remoteModuleBase = getModuleBaseAddress(hProcess, L"MpOav.dll");
    if (!remoteModuleBase) {
        std::wcout << L"[*] MpOav.dll not loaded in process " << pid << L" - skipping" << std::endl;
        CloseHandle(hProcess);
        return false; // Module not loaded, no patch possible
    }

    std::wcout << L"[*] Found MpOav.dll at base address: 0x" << std::hex << remoteModuleBase << std::dec << std::endl;

    // Get the remote function address using PE parsing
    DWORD_PTR remoteProcAddr = getRemoteFunctionAddressByPE(hProcess, remoteModuleBase, "DllGetClassObject");

    if (remoteProcAddr == 0) {
        std::wcerr << L"[!] Failed to locate DllGetClassObject in process: " << pid << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[*] DllGetClassObject located at: 0x" << std::hex << remoteProcAddr << std::dec << std::endl;

    // Read the first 6 bytes of the function
    BYTE buffer[6];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)remoteProcAddr, &buffer, 6, &bytesRead) || bytesRead != 6) {
        std::wcerr << L"[!] Failed to read memory in process: " << pid << L" (Error: " << GetLastError() << L")" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Log the actual bytes found for analysis
    std::wcout << L"[*] DllGetClassObject bytes in PID " << pid << L": ";
    for (int i = 0; i < 6; i++) {
        std::wcout << L"0x" << std::hex << std::setfill(L'0') << std::setw(2) << (int)buffer[i] << L" ";
    }
    std::wcout << std::dec << std::endl;

    // Check for the specific AMSI bypass pattern: MOV EAX, 0xFFFFFFFF; RET
    BYTE bypassBytes[6] = { 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };
    if (memcmp(buffer, bypassBytes, 6) == 0) {
        std::wcout << L"[!] AMSI BYPASS DETECTED - MpOav.dll is patched in process PID: " << pid << std::endl;
        std::wcout << L"    Detected pattern: MOV EAX, 0xFFFFFFFF; RET at address 0x" << std::hex << remoteProcAddr << std::dec << std::endl;
        CloseHandle(hProcess);
        return true;
    }

    // Check for other common bypass patterns
    // Pattern 2: XOR EAX, EAX; RET (0x33, 0xC0, 0xC3)
    BYTE bypassBytes2[3] = { 0x33, 0xC0, 0xC3 };
    if (memcmp(buffer, bypassBytes2, 3) == 0) {
        std::wcout << L"[!] AMSI BYPASS DETECTED - Alternative pattern in process PID: " << pid << std::endl;
        std::wcout << L"    Detected pattern: XOR EAX, EAX; RET at address 0x" << std::hex << remoteProcAddr << std::dec << std::endl;
        CloseHandle(hProcess);
        return true;
    }

    // Pattern 3: MOV EAX, 0; RET (0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
    BYTE bypassBytes3[6] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    if (memcmp(buffer, bypassBytes3, 6) == 0) {
        std::wcout << L"[!] AMSI BYPASS DETECTED - Zero return pattern in process PID: " << pid << std::endl;
        std::wcout << L"    Detected pattern: MOV EAX, 0; RET at address 0x" << std::hex << remoteProcAddr << std::dec << std::endl;
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

HMODULE MpOavPatchDetector::getModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return nullptr;
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        wchar_t szModName[MAX_PATH];
        if (GetModuleBaseNameW(hProcess, hMods[i], szModName, MAX_PATH)) {
            if (_wcsicmp(szModName, moduleName) == 0) {
                return hMods[i];
            }
        }
    }

    return nullptr;
}

DWORD_PTR MpOavPatchDetector::getRemoteFunctionAddressByPE(HANDLE hProcess, HMODULE remoteModuleBase, const char* functionName) {
    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, remoteModuleBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return 0;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders;
    DWORD_PTR ntHeadersAddr = (DWORD_PTR)remoteModuleBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return 0;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    // Find export directory
    DWORD exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    DWORD_PTR exportDirAddr = (DWORD_PTR)remoteModuleBase + exportDirRVA;
    if (!ReadProcessMemory(hProcess, (LPCVOID)exportDirAddr, &exportDir, sizeof(exportDir), &bytesRead)) {
        return 0;
    }

    // Read function name table
    std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
    DWORD_PTR nameTableAddr = (DWORD_PTR)remoteModuleBase + exportDir.AddressOfNames;
    if (!ReadProcessMemory(hProcess, (LPCVOID)nameTableAddr, nameRVAs.data(),
        exportDir.NumberOfNames * sizeof(DWORD), &bytesRead)) {
        return 0;
    }

    // Read ordinal table
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    DWORD_PTR ordinalTableAddr = (DWORD_PTR)remoteModuleBase + exportDir.AddressOfNameOrdinals;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ordinalTableAddr, ordinals.data(),
        exportDir.NumberOfNames * sizeof(WORD), &bytesRead)) {
        return 0;
    }

    // Read function address table
    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);
    DWORD_PTR functionTableAddr = (DWORD_PTR)remoteModuleBase + exportDir.AddressOfFunctions;
    if (!ReadProcessMemory(hProcess, (LPCVOID)functionTableAddr, functionRVAs.data(),
        exportDir.NumberOfFunctions * sizeof(DWORD), &bytesRead)) {
        return 0;
    }

    // Search for the function
    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        char funcName[256];
        DWORD_PTR funcNameAddr = (DWORD_PTR)remoteModuleBase + nameRVAs[i];
        if (!ReadProcessMemory(hProcess, (LPCVOID)funcNameAddr, funcName, sizeof(funcName), &bytesRead)) {
            continue;
        }
        funcName[255] = '\0'; // Ensure null termination

        if (strcmp(funcName, functionName) == 0) {
            WORD ordinal = ordinals[i];
            if (ordinal < exportDir.NumberOfFunctions) {
                return (DWORD_PTR)remoteModuleBase + functionRVAs[ordinal];
            }
        }
    }

    return 0;
}