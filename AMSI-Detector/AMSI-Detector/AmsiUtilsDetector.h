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
		// This function is now obsolete, as CLRMD is used for AMSI bypass detection.
        bool isAmsiUtilsBypassedInProcess(DWORD pid);
    };
}

#endif // AMSI_UTILS_DETECTOR_H