#include "AmsiUtilsDetector.h"
#include <iostream>
#include <psapi.h>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

using namespace detectors;

AmsiUtilsDetector::AmsiUtilsDetector() {
    // Constructor implementation
}

AmsiUtilsDetector::~AmsiUtilsDetector() {
    // Destructor implementation
}

bool AmsiUtilsDetector::isAmsiUtilsBypassedInProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[!] Failed to open process for AmsiUtils check: " << pid
            << L" (Error: " << GetLastError() << L")" << std::endl;
        return false;
    }

    std::wcout << L"[*] Scanning for .NET AmsiUtils bypass in process " << pid << std::endl;

    // First, try to find .NET CLR heap regions
    std::vector<DWORD_PTR> clrRegions = findCLRHeapRegions(hProcess);

    if (clrRegions.empty()) {
        std::wcout << L"[*] No .NET CLR regions found in process " << pid << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[*] Found " << clrRegions.size() << L" potential CLR regions" << std::endl;

    bool bypassDetected = false;

    // Scan each CLR region for AmsiUtils signatures
    for (DWORD_PTR region : clrRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)region, &mbi, sizeof(mbi))) {
            DWORD_PTR amsiUtilsAddr = scanForAmsiUtilsSignature(hProcess, region, mbi.RegionSize);

            if (amsiUtilsAddr != 0) {
                std::wcout << L"[*] Found potential AmsiUtils at address: 0x"
                    << std::hex << amsiUtilsAddr << std::dec << std::endl;

                // Check for amsiInitFailed bypass
                if (checkAmsiInitFailedBypass(hProcess, amsiUtilsAddr)) {
                    std::wcout << L"[!] AMSI BYPASS DETECTED - amsiInitFailed field manipulation in PID: "
                        << pid << std::endl;
                    bypassDetected = true;
                }

                // Check for amsiContext bypass
                if (checkAmsiContextBypass(hProcess, amsiUtilsAddr)) {
                    std::wcout << L"[!] AMSI BYPASS DETECTED - amsiContext corruption in PID: "
                        << pid << std::endl;
                    bypassDetected = true;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return bypassDetected;
}

std::vector<DWORD_PTR> AmsiUtilsDetector::findCLRHeapRegions(HANDLE hProcess) {
    std::vector<DWORD_PTR> clrRegions;
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    DWORD_PTR address = (DWORD_PTR)si.lpMinimumApplicationAddress;
    DWORD_PTR maxAddress = (DWORD_PTR)si.lpMaximumApplicationAddress;

    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
            // Look for committed memory regions that could contain .NET objects
            if (mbi.State == MEM_COMMIT &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                mbi.RegionSize > 0x1000) { // At least 4KB

                // Try to read a small sample to check for .NET signatures
                BYTE sample[256];
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample, sizeof(sample), &bytesRead)) {
                    // Look for common .NET metadata signatures
                    bool hasNetSignature = false;
                    for (size_t i = 0; i < bytesRead - 4; i++) {
                        // Check for .NET type table signatures or method table patterns
                        if ((sample[i] == 0x42 && sample[i + 1] == 0x53 && sample[i + 2] == 0x4A && sample[i + 3] == 0x42) || // BSJB
                            (sample[i] == 0x4D && sample[i + 1] == 0x5A) || // MZ header
                            (memcmp(&sample[i], "System.Management.Automation",
                                min(strlen("System.Management.Automation"), bytesRead - i)) == 0)) {
                            hasNetSignature = true;
                            break;
                        }
                    }

                    if (hasNetSignature) {
                        clrRegions.push_back((DWORD_PTR)mbi.BaseAddress);
                    }
                }
            }
            address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        else {
            address += si.dwPageSize;
        }
    }

    return clrRegions;
}

DWORD_PTR AmsiUtilsDetector::scanForAmsiUtilsSignature(HANDLE hProcess, DWORD_PTR baseAddr, SIZE_T size) {
    const SIZE_T CHUNK_SIZE = 4096;
    std::vector<BYTE> buffer(CHUNK_SIZE);

    for (SIZE_T offset = 0; offset < size; offset += CHUNK_SIZE) {
        SIZE_T readSize = min(CHUNK_SIZE, size - offset);
        SIZE_T bytesRead;

        if (ReadProcessMemory(hProcess, (LPCVOID)(baseAddr + offset),
            buffer.data(), readSize, &bytesRead)) {

            // Search for AmsiUtils class name or related signatures
            std::string amsiUtilsStr = "AmsiUtils";
            std::string amsiInitFailedStr = "amsiInitFailed";
            std::string amsiContextStr = "amsiContext";

            for (SIZE_T i = 0; i < bytesRead - amsiUtilsStr.length(); i++) {
                if (memcmp(&buffer[i], amsiUtilsStr.c_str(), amsiUtilsStr.length()) == 0) {
                    // Found AmsiUtils string, this might be near the class metadata
                    return baseAddr + offset + i;
                }
            }

            // Also look for the field names
            for (SIZE_T i = 0; i < bytesRead - amsiInitFailedStr.length(); i++) {
                if (memcmp(&buffer[i], amsiInitFailedStr.c_str(), amsiInitFailedStr.length()) == 0 ||
                    memcmp(&buffer[i], amsiContextStr.c_str(), amsiContextStr.length()) == 0) {
                    return baseAddr + offset + i;
                }
            }
        }
    }

    return 0;
}

bool AmsiUtilsDetector::checkAmsiInitFailedBypass(HANDLE hProcess, DWORD_PTR amsiUtilsAddr) {
    // This is a simplified check - in reality, we'd need to parse .NET metadata
    // to find the exact field locations. For now, we'll scan around the found address.

    const SIZE_T SCAN_RANGE = 0x1000; // 4KB around the found address
    std::vector<BYTE> buffer(SCAN_RANGE);
    SIZE_T bytesRead;

    DWORD_PTR scanStart = (amsiUtilsAddr > SCAN_RANGE / 2) ? amsiUtilsAddr - SCAN_RANGE / 2 : 0;

    if (ReadProcessMemory(hProcess, (LPCVOID)scanStart, buffer.data(), SCAN_RANGE, &bytesRead)) {
        // Look for boolean field patterns that might indicate amsiInitFailed = true
        // In .NET, static boolean fields are often stored as 4-byte integers (0 or 1)

        std::string fieldName = "amsiInitFailed";
        for (SIZE_T i = 0; i < bytesRead - fieldName.length() - 4; i++) {
            if (memcmp(&buffer[i], fieldName.c_str(), fieldName.length()) == 0) {
                // Found the field name, check nearby memory for the value
                for (int offset = -32; offset <= 32; offset += 4) {
                    SIZE_T valueIndex = i + fieldName.length() + offset;
                    if (valueIndex < bytesRead - 4) {
                        DWORD value = *(DWORD*)&buffer[valueIndex];
                        // Check if this looks like a boolean true value (1 or 0xFFFFFFFF)
                        if (value == 1 || value == 0xFFFFFFFF) {
                            std::wcout << L"[*] Suspicious amsiInitFailed value found: 0x"
                                << std::hex << value << std::dec << std::endl;
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

bool AmsiUtilsDetector::checkAmsiContextBypass(HANDLE hProcess, DWORD_PTR amsiUtilsAddr) {
    const SIZE_T SCAN_RANGE = 0x1000;
    std::vector<BYTE> buffer(SCAN_RANGE);
    SIZE_T bytesRead;

    DWORD_PTR scanStart = (amsiUtilsAddr > SCAN_RANGE / 2) ? amsiUtilsAddr - SCAN_RANGE / 2 : 0;

    if (ReadProcessMemory(hProcess, (LPCVOID)scanStart, buffer.data(), SCAN_RANGE, &bytesRead)) {
        std::string contextField = "amsiContext";

        for (SIZE_T i = 0; i < bytesRead - contextField.length() - 8; i++) {
            if (memcmp(&buffer[i], contextField.c_str(), contextField.length()) == 0) {
                // Found amsiContext field, check for IntPtr corruption
                for (int offset = -32; offset <= 32; offset += sizeof(void*)) {
                    SIZE_T ptrIndex = i + contextField.length() + offset;
                    if (ptrIndex < bytesRead - sizeof(void*)) {
                        void* ptrValue = *(void**)&buffer[ptrIndex];

                        // Check if the pointer has been zeroed or corrupted
                        if (ptrValue == nullptr) {
                            std::wcout << L"[*] amsiContext appears to be nullified" << std::endl;
                            return true;
                        }

                        // Additional check: try to read what the pointer points to
                        if (ptrValue != nullptr) {
                            DWORD testValue;
                            SIZE_T testBytesRead;
                            if (ReadProcessMemory(hProcess, ptrValue, &testValue, sizeof(testValue), &testBytesRead)) {
                                // If we can read it and it's zero, might be corrupted
                                if (testValue == 0 && testBytesRead == sizeof(testValue)) {
                                    std::wcout << L"[*] amsiContext points to zeroed memory" << std::endl;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}