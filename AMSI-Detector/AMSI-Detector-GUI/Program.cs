using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AMSI_Detector_GUI
{
    internal static class Program
    {
        private static NotifyIcon notifyIcon;
        private static CancellationTokenSource cancellationTokenSource;
        private static bool isBackgroundMode = false;
        private static List<int> detectedBypassProcessIds = new List<int>();
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--background")
            {
                isBackgroundMode = true;
                RunInBackground();
                return;
            }


            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new AMSIDetector());
        }

        static void RunInBackground()
        {
            try
            {
                // Initialize system tray icon
                InitializeNotifyIcon();

                // Start background monitoring
                cancellationTokenSource = new CancellationTokenSource();
                StartBackgroundMonitoring(cancellationTokenSource.Token);

                // Show initial notification
                ShowNotification("AMSI Background Monitor Started",
                    "Monitoring for AMSI bypasses every 15 seconds. Right-click icon to exit.",
                    ToolTipIcon.Info);

                // Keep the application running
                Application.Run();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start background monitoring: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                CleanupResources();
            }
        }

        static void InitializeNotifyIcon()
        {
            notifyIcon = new NotifyIcon();
            notifyIcon.Icon = SystemIcons.Shield; // Use shield icon for security tool
            notifyIcon.Text = "AMSI Background Monitor";
            notifyIcon.Visible = true;

            // Create context menu
            var contextMenu = new ContextMenuStrip();

            var statusItem = new ToolStripMenuItem("AMSI Monitor - Running");
            statusItem.Enabled = false;
            contextMenu.Items.Add(statusItem);

            contextMenu.Items.Add(new ToolStripSeparator());

            var runScanItem = new ToolStripMenuItem("Run Scan Now");
            runScanItem.Click += (s, e) => Task.Run(() => RunSingleScan());
            contextMenu.Items.Add(runScanItem);

            var showLogsItem = new ToolStripMenuItem("Open Logs Folder");
            showLogsItem.Click += ShowLogsFolder;
            contextMenu.Items.Add(showLogsItem);

            contextMenu.Items.Add(new ToolStripSeparator());

            var exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += ExitApplication;
            contextMenu.Items.Add(exitItem);

            notifyIcon.ContextMenuStrip = contextMenu;

            // Double-click to run manual scan
            notifyIcon.DoubleClick += (s, e) => Task.Run(() => RunSingleScan());

            // Click handler for bypass notifications
            notifyIcon.BalloonTipClicked += OnNotificationClicked;
        }

        static async void StartBackgroundMonitoring(CancellationToken cancellationToken)
        {
            int scanCount = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    scanCount++;
                    await RunScanAsync(scanCount);
                    await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break; // Normal cancellation
                }
                catch (Exception ex)
                {
                    ShowNotification("Background Scan Error",
                        $"Scan #{scanCount} failed: {ex.Message}",
                        ToolTipIcon.Error);

                    // Continue monitoring even if one scan fails
                    await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
                }
            }
        }

        static async Task RunScanAsync(int scanNumber = 0)
        {
            var output = new StringBuilder();
            bool hasError = false;

            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "AMSI-Detector.exe";
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();

                    string stdout = process.StandardOutput.ReadToEnd();
                    string stderr = process.StandardError.ReadToEnd();

                    process.WaitForExit();

                    output.AppendLine(stdout);

                    if (!string.IsNullOrWhiteSpace(stderr))
                    {
                        output.AppendLine("[ERROR]");
                        output.AppendLine(stderr);
                        hasError = true;
                    }
                }

                // Save to log file
                await SaveToLogAsync(output.ToString(), hasError);

                // Analyze results and notify user
                await AnalyzeAndNotify(output.ToString(), scanNumber);
            }
            catch (Exception ex)
            {
                string errorMsg = $"❌ Background scan failed: {ex.Message}";
                output.AppendLine(errorMsg);
                await SaveToLogAsync(output.ToString(), true);

                ShowNotification("Scan Error", errorMsg, ToolTipIcon.Error);
            }
        }

        static void RunSingleScan()
        {
            ShowNotification("Manual Scan", "Running AMSI scan...", ToolTipIcon.Info);
            RunScanAsync().Wait();
        }

        static async Task SaveToLogAsync(string content, bool hasError)
        {
            try
            {
                string logsDir = Path.Combine(Application.StartupPath, "logs");
                if (!Directory.Exists(logsDir))
                    Directory.CreateDirectory(logsDir);

                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string fileName = hasError ? $"scan_error_{timestamp}.log" : $"scan_{timestamp}.log";
                string logFilePath = Path.Combine(logsDir, fileName);

                await Task.Run(() => File.WriteAllText(logFilePath, content));
            }
            catch (Exception ex)
            {
                ShowNotification("Log Error", $"Failed to save log: {ex.Message}", ToolTipIcon.Warning);
            }
        }

        static async Task AnalyzeAndNotify(string scanOutput, int scanNumber)
        {
            try
            {
                if (scanOutput.Contains("[*] No PowerShell processes found."))
                {
                    // Only show this notification occasionally to avoid spam
                    if (scanNumber % 10 == 1) // Every 10th scan (~2.5 minutes)
                    {
                        ShowNotification("No PowerShell Processes",
                            "No PowerShell processes found to scan.",
                            ToolTipIcon.Info);
                    }
                    return;
                }

                // Check for AMSI bypasses and extract process IDs
                if (scanOutput.Contains("ALERT") || scanOutput.Contains("[!]"))
                {
                    detectedBypassProcessIds.Clear(); // Clear previous detections
                    ExtractBypassProcessIds(scanOutput);

                    string title = "⚠️ AMSI Bypass Detected!";
                    string message = ExtractAlertSummary(scanOutput);

                    if (detectedBypassProcessIds.Count > 0)
                    {
                        message += "\n\nClick this notification to terminate the bypassed processes.";
                    }

                    ShowNotification(title, message, ToolTipIcon.Warning);
                }
                else if (scanOutput.Contains("No AMSI bypasses") || scanOutput.Contains("All scanned"))
                {
                    detectedBypassProcessIds.Clear(); // Clear when all clear

                    // Only show "all clear" notifications occasionally
                    if (scanNumber % 20 == 1) // Every 20th scan (~5 minutes)
                    {
                        ShowNotification("All Clear",
                            "No AMSI bypasses detected in current scan.",
                            ToolTipIcon.Info);
                    }
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Analysis Error",
                    $"Failed to analyze scan results: {ex.Message}",
                    ToolTipIcon.Error);
            }
        }

        static string ExtractAlertSummary(string scanOutput)
        {
            var lines = scanOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            var alerts = new List<string>();

            foreach (var line in lines)
            {
                string trimmed = line.Trim();
                if (trimmed.Contains("ALERT") || trimmed.StartsWith("[!]"))
                {
                    string alert = trimmed.Replace("[!]", "").Replace("ALERT", "").Trim();
                    if (!string.IsNullOrWhiteSpace(alert) && alerts.Count < 3) // Limit to 3 alerts
                    {
                        alerts.Add(alert);
                    }
                }
            }

            return alerts.Count > 0 ? string.Join("\n", alerts) : "AMSI bypass activity detected!";
        }

        static void ExtractBypassProcessIds(string scanOutput)
        {
            var lines = scanOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                string trimmed = line.Trim();

                // Look for process information patterns
                // Example: "Process: powershell.exe (PID: 1234)"
                if (trimmed.Contains("Process:") && trimmed.Contains("PID:"))
                {
                    try
                    {
                        int pidStart = trimmed.IndexOf("PID:") + 4;
                        int pidEnd = trimmed.IndexOf(")", pidStart);
                        if (pidEnd == -1) pidEnd = trimmed.Length;

                        string pidString = trimmed.Substring(pidStart, pidEnd - pidStart).Trim();
                        if (int.TryParse(pidString, out int processId))
                        {
                            if (!detectedBypassProcessIds.Contains(processId))
                            {
                                detectedBypassProcessIds.Add(processId);
                            }
                        }
                    }
                    catch { } // Ignore parsing errors
                }

                // Alternative pattern: "[!] PID 1234: bypass detected"
                else if ((trimmed.StartsWith("[!]") || trimmed.Contains("ALERT")) && trimmed.Contains("PID"))
                {
                    try
                    {
                        var words = trimmed.Split(' ');
                        for (int i = 0; i < words.Length - 1; i++)
                        {
                            if (words[i].Equals("PID", StringComparison.OrdinalIgnoreCase))
                            {
                                string pidString = words[i + 1].Replace(":", "").Trim();
                                if (int.TryParse(pidString, out int processId))
                                {
                                    if (!detectedBypassProcessIds.Contains(processId))
                                    {
                                        detectedBypassProcessIds.Add(processId);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    catch { } // Ignore parsing errors
                }
            }
        }

        static void OnNotificationClicked(object sender, EventArgs e)
        {
            if (detectedBypassProcessIds.Count > 0)
            {
                ShowTerminateProcessDialog();
            }
        }

        static void ShowTerminateProcessDialog()
        {
            try
            {
                var validProcesses = new List<(int pid, string name)>();

                // Check which processes are still running
                foreach (int pid in detectedBypassProcessIds)
                {
                    try
                    {
                        var process = Process.GetProcessById(pid);
                        validProcesses.Add((pid, process.ProcessName));
                    }
                    catch
                    {
                        // Process no longer exists, ignore
                    }
                }

                if (validProcesses.Count == 0)
                {
                    ShowNotification("No Active Processes",
                        "The bypassed processes are no longer running.",
                        ToolTipIcon.Info);
                    detectedBypassProcessIds.Clear();
                    return;
                }

                // Create process list message
                var processListBuilder = new StringBuilder();
                processListBuilder.AppendLine("The following processes have AMSI bypasses detected:");
                processListBuilder.AppendLine();

                foreach (var (pid, name) in validProcesses)
                {
                    processListBuilder.AppendLine($"• {name} (PID: {pid})");
                }

                processListBuilder.AppendLine();
                processListBuilder.AppendLine("Do you want to terminate these processes?");
                processListBuilder.AppendLine();
                processListBuilder.AppendLine("⚠️ WARNING: This will forcefully close the processes and may cause data loss!");

                var result = MessageBox.Show(
                    processListBuilder.ToString(),
                    "Terminate Bypassed Processes",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);

                if (result == DialogResult.Yes)
                {
                    TerminateProcesses(validProcesses);
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Error",
                    $"Failed to show process termination dialog: {ex.Message}",
                    ToolTipIcon.Error);
            }
        }

        static void TerminateProcesses(List<(int pid, string name)> processes)
        {
            int terminated = 0;
            int failed = 0;
            var failedProcesses = new List<string>();

            foreach (var (pid, name) in processes)
            {
                try
                {
                    var process = Process.GetProcessById(pid);
                    process.Kill();
                    process.WaitForExit(5000); // Wait up to 5 seconds
                    terminated++;
                }
                catch (Exception ex)
                {
                    failed++;
                    failedProcesses.Add($"{name} (PID: {pid}) - {ex.Message}");
                }
            }

            // Clear the detected processes list
            detectedBypassProcessIds.Clear();

            // Show result notification
            string resultMessage;
            ToolTipIcon resultIcon;

            if (terminated > 0 && failed == 0)
            {
                resultMessage = $"✅ Successfully terminated {terminated} process(es).";
                resultIcon = ToolTipIcon.Info;
            }
            else if (terminated > 0 && failed > 0)
            {
                resultMessage = $"⚠️ Terminated {terminated} process(es), but {failed} failed to terminate.";
                resultIcon = ToolTipIcon.Warning;
            }
            else
            {
                resultMessage = $"❌ Failed to terminate any processes.";
                resultIcon = ToolTipIcon.Error;
            }

            if (failed > 0 && failedProcesses.Count <= 3)
            {
                resultMessage += "\n\nFailed processes:\n" + string.Join("\n", failedProcesses.Take(3));
            }

            ShowNotification("Process Termination Result", resultMessage, resultIcon);
        }

        static void ShowNotification(string title, string message, ToolTipIcon icon)
        {
            if (notifyIcon != null)
            {
                // Limit message length for balloon tip
                string briefMessage = message.Length > 200 ? message.Substring(0, 200) + "..." : message;

                notifyIcon.BalloonTipTitle = title;
                notifyIcon.BalloonTipText = briefMessage;
                notifyIcon.BalloonTipIcon = icon;
                notifyIcon.ShowBalloonTip(5000); // Show for 5 seconds
            }
        }

        static void ShowLogsFolder(object sender, EventArgs e)
        {
            try
            {
                string logsDir = Path.Combine(Application.StartupPath, "logs");
                if (Directory.Exists(logsDir))
                {
                    Process.Start("explorer.exe", logsDir);
                }
                else
                {
                    ShowNotification("No Logs", "Logs directory not found.", ToolTipIcon.Info);
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Error", $"Failed to open logs folder: {ex.Message}", ToolTipIcon.Error);
            }
        }

        static void ExitApplication(object sender, EventArgs e)
        {
            CleanupResources();
            Application.Exit();
        }

        static void CleanupResources()
        {
            try
            {
                cancellationTokenSource?.Cancel();
                cancellationTokenSource?.Dispose();

                if (notifyIcon != null)
                {
                    notifyIcon.Visible = false;
                    notifyIcon.Dispose();
                }
            }
            catch (Exception ex)
            {
                // Log cleanup errors but don't show notifications during shutdown
                Debug.WriteLine($"Cleanup error: {ex.Message}");
            }
        }
    }
}
