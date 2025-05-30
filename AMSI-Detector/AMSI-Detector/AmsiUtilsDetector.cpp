#include "AmsiUtilsDetector.h"
#include <iostream>

using namespace detectors;

AmsiUtilsDetector::AmsiUtilsDetector() {
    // Constructor implementation (can be empty)
}

AmsiUtilsDetector::~AmsiUtilsDetector() {
    // Destructor implementation (can be empty)
}

// This function is now obsolete, as CLRMD is used for AMSI bypass detection.
// You may remove calls to this function from your codebase.
bool AmsiUtilsDetector::isAmsiUtilsBypassedInProcess(DWORD pid) {
    std::wcout << L"[AmsiUtilsDetector] Skipped: CLRMD-based detection is now used." << std::endl;
    return false;
}
