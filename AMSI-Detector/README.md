# AMSI Detector

This project provides both CLI and GUI versions of an AMSI (Anti-Malware Scan Interface) detection tool. It can detect various AMSI bypass techniques and modifications to the AMSI system.

## Prerequisites

### For CLI Version (C++)
- Visual Studio 2019 or later
- Windows SDK 10.0 or later
- C++ Desktop Development workload
- x64 platform tools
- .NET 8.0 SDK

### For GUI Version (C#)
- Visual Studio 2019 or later
- .NET Framework 4.7.2 or later
- Windows Forms development tools
- .NET 8.0 SDK

## Building the Project

The project consists of three components that need to be built together:
1. AMSI-Detector (CLI version)
2. AMSI-Detector-GUI (GUI version)
3. AmsiClrmdHelper (Required helper library)

To build the entire solution:

1. Open `AMSI-Detector.sln` in Visual Studio
2. Set the build configuration to `Release`
3. For CLI version: Set platform to `x64`
4. For GUI version: Set platform to `Any CPU`
5. Build the entire solution (F7 or Build > Build Solution)

This will generate:
- CLI executable in `AMSI-Detector/x64/Release/`
- GUI executable in `AMSI-Detector-GUI/bin/Release/`
- Required helper files in `AMSI-Detector\AmsiClrmdHelper\bin\Release\net8.0\`

> **Important**: Always build the entire solution to ensure all components are properly compiled and up to date.

## Required Files

### CLI Version
The following files are required to run the CLI version:
- `AMSI-Detector.exe` (main executable)
- All files from `AMSI-Detector\AmsiClrmdHelper\bin\Release\net8.0\`:
  - `AmsiClrmdHelper.dll`
  - `Microsoft.Diagnostics.Runtime.dll`
  - `Microsoft.Diagnostics.Runtime.Utilities.dll`
  - `System.Collections.Immutable.dll`
  - `System.Memory.dll`
  - `System.Reflection.Metadata.dll`
  - `System.Runtime.CompilerServices.Unsafe.dll`
  - `System.Text.Encoding.CodePages.dll`
  - `System.Text.Json.dll`
  - `System.Threading.Tasks.Dataflow.dll`
  - `System.ValueTuple.dll`

### GUI Version
The following files are required to run the GUI version:
- `AMSI-Detector-GUI.exe` (main executable)
- `AMSI-Detector-GUI.exe.config` (configuration file)
- All files in the `Resources` directory
- `AMSI-Detector.exe` (CLI version executable)
- All files from `AMSI-Detector\AmsiClrmdHelper\bin\Release\net8.0\` (same as CLI version)

## Running the Application

### CLI Version
1. Open Command Prompt
2. Navigate to the directory containing `AMSI-Detector.exe`
3. Ensure all required files from `AmsiClrmdHelper\bin\Release\net8.0\` are in the same directory
4. Run the executable:
```cmd
AMSI-Detector.exe
```

### GUI Version
1. Double-click `AMSI-Detector-GUI.exe`
2. Ensure all required files are present:
   - `AMSI-Detector.exe` in the same directory
   - All files from `AmsiClrmdHelper\bin\Release\net8.0\` in the same directory
3. The GUI interface will open, allowing you to:
   - Scan for AMSI bypasses
   - View detailed detection results
   - Monitor AMSI status in real-time

## Features

### CLI Version
- Command-line interface for automated scanning
- Detection of AMSI bypass techniques
- Detailed logging of findings
- Integration with system monitoring

### GUI Version
- User-friendly interface
- Real-time AMSI status monitoring
- Detailed detection reports
- Visual representation of findings
- Easy-to-use controls for scanning and monitoring

## Troubleshooting

If you encounter any issues:

1. Ensure you're running the application as Administrator
2. Verify all required files are present in the correct locations:
   - Check that all files from `AmsiClrmdHelper\bin\Release\net8.0\` are in the same directory as the executable
   - For GUI version, ensure `AMSI-Detector.exe` is present
3. Check that you have the necessary permissions
4. Make sure no antivirus software is blocking the application
5. Verify that .NET 8.0 runtime is installed on the system

## Security Note

This tool is designed for security research and testing purposes. Always use it responsibly and only in controlled environments.