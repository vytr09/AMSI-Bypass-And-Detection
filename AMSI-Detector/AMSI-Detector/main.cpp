#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include "MpOavPatchDetector.h"
#include "AmsiUtilsDetector.h"

void printBanner() {
    std::wcout << L"================================================================" << std::endl;
    std::wcout << L"=== AMSI Bypass Detector (MpOav.dll Patch Detection) v1.0 ===" << std::endl;
    std::wcout << L"================================================================" << std::endl;
    std::wcout << L"Scanning for AMSI bypass techniques in PowerShell processes..." << std::endl;
    std::wcout << L"================================================================" << std::endl;
}

std::vector<DWORD> findPowerShellProcesses() {
    std::vector<DWORD> powerShellPids;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to create process snapshot (Error: " << GetLastError() << L")" << std::endl;
        return powerShellPids;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        std::wcerr << L"[!] Failed to get first process (Error: " << GetLastError() << L")" << std::endl;
        return powerShellPids;
    }

    do {
        std::wstring exe(pe.szExeFile);

        // Check for both Windows PowerShell and PowerShell Core
        if (_wcsicmp(exe.c_str(), L"powershell.exe") == 0 ||
            _wcsicmp(exe.c_str(), L"pwsh.exe") == 0) {
            powerShellPids.push_back(pe.th32ProcessID);
            std::wcout << L"[*] Found PowerShell process: " << exe << L" (PID: " << pe.th32ProcessID << L")" << std::endl;
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
    return powerShellPids;
}

int main() {
    printBanner();

    // Find all PowerShell processes
    std::vector<DWORD> powerShellPids = findPowerShellProcesses();

    if (powerShellPids.empty()) {
        std::wcout << L"[*] No PowerShell processes found." << std::endl;
        system("pause");
        return 0;
    }

    std::wcout << L"\n[*] Found " << powerShellPids.size() << L" PowerShell process(es). Checking for AMSI bypass..." << std::endl;
    std::wcout << L"================================================================" << std::endl;

    // Check each PowerShell process for AMSI bypass
    detectors::MpOavPatchDetector mpoavDetector;
    detectors::AmsiUtilsDetector amsiUtilsDetector;
    bool foundBypass = false;
    int processesChecked = 0;

    for (DWORD pid : powerShellPids) {
        std::wcout << L"\n[*] Checking process PID: " << pid << std::endl;
        std::wcout << L"================================================================" << std::endl;

        // Check for MpOav.dll patching
        std::wcout << L"[*] Checking for MpOav.dll patches..." << std::endl;
        bool mpoavBypass = mpoavDetector.isMpOavPatchedInProcess(pid);

        // Check for AmsiUtils field manipulation
        std::wcout << L"[*] Checking for AmsiUtils field manipulation..." << std::endl;
        bool amsiUtilsBypass = amsiUtilsDetector.isAmsiUtilsBypassedInProcess(pid);

        if (mpoavBypass || amsiUtilsBypass) {
            foundBypass = true;
            std::wcout << L"[!] WARNING: AMSI bypass detected in process " << pid << L"!" << std::endl;
            if (mpoavBypass) {
                std::wcout << L"    - MpOav.dll patch detected" << std::endl;
            }
            if (amsiUtilsBypass) {
                std::wcout << L"    - AmsiUtils field manipulation detected" << std::endl;
            }
        }
        else {
            std::wcout << L"[+] Process " << pid << L" appears clean." << std::endl;
        }
        processesChecked++;
    }

    // Summary
    std::wcout << L"\n================================================================" << std::endl;
    std::wcout << L"=== SCAN SUMMARY ===" << std::endl;
    std::wcout << L"Processes scanned: " << processesChecked << std::endl;

    if (foundBypass) {
        std::wcout << L"[!] ALERT: AMSI bypass detected in one or more processes!" << std::endl;
        std::wcout << L"[!] This may indicate malicious activity or security testing." << std::endl;
        std::wcout << L"[!] Detected bypass types may include:" << std::endl;
        std::wcout << L"    - MpOav.dll DllGetClassObject patching" << std::endl;
        std::wcout << L"    - AmsiUtils.amsiInitFailed field manipulation" << std::endl;
        std::wcout << L"    - AmsiUtils.amsiContext corruption" << std::endl;
    }
    else {
        std::wcout << L"[+] No AMSI bypasses detected in any PowerShell process." << std::endl;
        std::wcout << L"[+] All scanned processes appear to have intact AMSI protection." << std::endl;
    }

    std::wcout << L"================================================================" << std::endl;
    std::wcout << L"\nPress any key to exit..." << std::endl;
    system("pause");

    return foundBypass ? 1 : 0;  // Return 1 if bypass detected, 0 if clean
}