#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include "MpOavPatchDetector.h"
//#include "AmsiUtilsDetector.h"

void printBanner() {
    std::wcout << L"================================================================\n";
    std::wcout << L"===           AMSI Bypass Detector v1.0 (MpOav/CLRMD)        ===\n";
    std::wcout << L"================================================================\n";
    std::wcout << L"Scanning for AMSI bypass techniques in PowerShell processes...\n";
    std::wcout << L"================================================================\n";
}

void printProcessHeader(DWORD pid, const std::wstring& exe) {
    std::wcout << L"\n----------------------------------------------------------------\n";
    std::wcout << L"[>] Process: " << exe << L" (PID: " << pid << L")\n";
    std::wcout << L"----------------------------------------------------------------\n";
}

void printBypassSummary(bool mpoav, bool clrmd, const std::wstring& clrmdOutput) {
    std::wcout << L"[!] AMSI BYPASS DETECTED!\n";
    if (mpoav)  std::wcout << L"    - MpOav.dll patch detected\n";
    if (clrmd) {
        std::wcout << L"    - CLRMD detected bypass:\n";
        // Indent each line of clrmdOutput
        std::wistringstream iss(clrmdOutput);
        std::wstring line;
        while (std::getline(iss, line)) {
            if (!line.empty())
                std::wcout << L"        " << line << L"\n";
        }
    }
}

void printProcessClean() {
    std::wcout << L"[+] No AMSI bypass detected in this process.\n";
}

void printScanSummary(int processesChecked, bool foundBypass, bool foundMpOavBypass, bool foundClrmdInitFailedBypass, bool foundClrmdContextBypass, bool foundClrmdScanContentBypass) {
    std::wcout << L"\n================================================================\n";
    std::wcout << L"=== SCAN SUMMARY ==============================================\n";
    std::wcout << L"Processes scanned: " << processesChecked << L"\n";
    if (foundBypass) {
        std::wcout << L"[!] ALERT: AMSI bypass detected in one or more processes!\n";
        std::wcout << L"[!] This may indicate malicious activity or security testing.\n";
        std::wcout << L"[!] Detected bypass types:\n";
        if (foundMpOavBypass)
            std::wcout << L"    - MpOav.dll DllGetClassObject patching\n";
        if (foundClrmdInitFailedBypass)
            std::wcout << L"    - AmsiUtils.amsiInitFailed field manipulation\n";
        if (foundClrmdContextBypass)
            std::wcout << L"    - AmsiUtils.amsiContext corruption\n";
        if (foundClrmdScanContentBypass)
            std::wcout << L"    - AmsiUtils.ScanContent method pointer swap\n";
    }
    else {
        std::wcout << L"[+] No AMSI bypasses detected in any PowerShell process.\n";
        std::wcout << L"[+] All scanned processes appear to have intact AMSI protection.\n";
    }
    std::wcout << L"================================================================\n";
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

bool CheckAmsiBypassWithClrmd(DWORD pid, std::wstring& output)
{
    std::wstring exePath = L"AmsiClrmdHelper.exe"; // Adjust path if needed
    std::wstring cmd = exePath + L" " + std::to_wstring(pid);

    // Set up pipes for output redirection
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return false;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    wchar_t cmdLine[512];
    wcsncpy_s(cmdLine, cmd.c_str(), _TRUNCATE);

    BOOL success = CreateProcessW(
        NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hWrite);

    if (!success) {
        CloseHandle(hRead);
        return false;
    }

    // Read output
    char buffer[256];
    DWORD bytesRead;
    std::string result;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        result += buffer;
    }
    CloseHandle(hRead);

    // Wait for process to exit and get exit code
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    output = std::wstring(result.begin(), result.end());
    return (exitCode == 1); // 1 = bypass detected, 0 = clean, 2 = error
}

int main() {
    bool foundMpOavBypass = false;
    bool foundAmsiUtilsBypass = false;
    bool foundClrmdInitFailedBypass = false;
    bool foundClrmdContextBypass = false;
    bool foundClrmdScanContentBypass = false;

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

    bool foundBypass = false;
    int processesChecked = 0;

    for (DWORD pid : powerShellPids) {
        std::wstring exeName = L"powershell.exe"; // Or get from PROCESSENTRY32W if available
        printProcessHeader(pid, exeName);

        std::wcout << L"  [*] Checking for MpOav.dll patches...\n";
        bool mpoavBypass = mpoavDetector.isMpOavPatchedInProcess(pid);

        std::wstring clrmdOutput;
        bool clrmdBypass = CheckAmsiBypassWithClrmd(pid, clrmdOutput);


        if (mpoavBypass) foundMpOavBypass = true;

        // Check for specific CLRMD bypasses in the output
        if (clrmdBypass) {
            std::wstring lowerOutput = clrmdOutput;
            std::transform(lowerOutput.begin(), lowerOutput.end(), lowerOutput.begin(), ::towlower);
            if (lowerOutput.find(L"amsiinitfailed set to true in defaultdomain") != std::wstring::npos)
                foundClrmdInitFailedBypass = true;
            if (lowerOutput.find(L"first 8 bytes are zeroed") != std::wstring::npos ||
                lowerOutput.find(L"amsicontext is null") != std::wstring::npos)
                foundClrmdContextBypass = true;
            if (lowerOutput.find(L"scancontent missing and method 'm' present in amsiutils") != std::wstring::npos)
                foundClrmdScanContentBypass = true;
        }


        if (mpoavBypass || clrmdBypass) {
            foundBypass = true;
            printBypassSummary(mpoavBypass, clrmdBypass, clrmdOutput);
        }
        else {
            printProcessClean();
        }
        processesChecked++;
    }

    printScanSummary(processesChecked, foundBypass, foundMpOavBypass, foundClrmdInitFailedBypass, foundClrmdContextBypass, foundClrmdScanContentBypass);

    system("pause");

    return foundBypass ? 1 : 0;  // Return 1 if bypass detected, 0 if clean
}