using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace AMSI_Detector_GUI
{
    public partial class AMSIDetector : Form
    {
        public AMSIDetector()
        {
            InitializeComponent();
        }

        private async void scanBtn_Click(object sender, EventArgs e)
        {
            string scannerPath = "AMSI-Detector.exe";
            string logsDir = Path.Combine(Application.StartupPath, "logs");

            try
            {
                if (!Directory.Exists(logsDir))
                    Directory.CreateDirectory(logsDir);

                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string logFilePath = Path.Combine(logsDir, $"scan_{timestamp}.log");

                var outputBuilder = new StringBuilder();
                var errorBuilder = new StringBuilder();

                await Task.Run(() =>
                {
                    using (var process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = scannerPath;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.RedirectStandardError = true;
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;

                        process.Start();

                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();

                        process.WaitForExit();

                        outputBuilder.Append(output);
                        errorBuilder.Append(error);
                    }
                });

                string rawOutput = outputBuilder.ToString();
                string errorOutput = errorBuilder.ToString();

                if (!string.IsNullOrWhiteSpace(errorOutput))
                {
                    File.WriteAllText(logFilePath, rawOutput + "\n[ERROR]\n" + errorOutput);
                }
                else
                {
                    File.WriteAllText(logFilePath, rawOutput);
                }

                if (rawOutput.Contains("[*] No PowerShell processes found."))
                {
                    MessageBox.Show("ℹ️ No PowerShell processes found. Please make sure at least one PowerShell instance is running to scan.",
                        "Scan Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                string formattedSummary = FormatScanResult(rawOutput);
                if (string.IsNullOrWhiteSpace(formattedSummary))
                    formattedSummary = "ℹ️ No PowerShell processes found or no AMSI-related information detected.";

                MessageBox.Show(formattedSummary, "AMSI Scan Result",
                    MessageBoxButtons.OK,
                    formattedSummary.Contains("❗") ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Scan failed:\n\n" + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string FormatScanResult(string rawLog)
        {
            var lines = rawLog.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var sb = new StringBuilder();

            bool inSummary = false;
            bool parsingBypassTypes = false;

            foreach (var line in lines)
            {
                string trimmed = line.Trim();

                // Bắt đầu phần SCAN SUMMARY
                if (trimmed.StartsWith("=== SCAN SUMMARY"))
                {
                    inSummary = true;
                    sb.AppendLine("🧪 Scan Summary:");
                    continue;
                }

                if (!inSummary)
                    continue;

                // Nếu gặp dòng bắt đầu phần mới, thoát khỏi parsingBypassTypes
                if (trimmed.StartsWith("===") || trimmed.StartsWith("[ERROR]"))
                {
                    parsingBypassTypes = false;
                    continue;
                }

                if (trimmed.StartsWith("Processes scanned:"))
                {
                    sb.AppendLine("  • Processes scanned: " + trimmed.Split(':').Last().Trim());
                    continue;
                }

                if (trimmed.Contains("ALERT"))
                {
                    sb.AppendLine("\n🚨 " + trimmed.Replace("[!]", "").Trim());
                    continue;
                }

                if (trimmed.StartsWith("[!]"))
                {
                    string msg = trimmed.Replace("[!]", "").Trim();
                    if (msg.StartsWith("Detected bypass types"))
                    {
                        sb.AppendLine("\n🔍 Detected bypass types:");
                        parsingBypassTypes = true;
                        continue;
                    }

                    sb.AppendLine("    ⚠️ " + msg);
                    continue;
                }

                if (trimmed.StartsWith("[+]"))
                {
                    string msg = trimmed.Replace("[+]", "").Trim();

                    if (msg.StartsWith("No AMSI bypasses") || msg.StartsWith("All scanned"))
                        sb.AppendLine("    ✅ " + msg);
                    else
                        sb.AppendLine("  • " + msg);
                }

                if (parsingBypassTypes)
                {
                    if (line.StartsWith("    ") || line.StartsWith("\t") || line.StartsWith("        "))
                    {
                        sb.AppendLine("      " + trimmed);
                    }
                    else
                    {
                        parsingBypassTypes = false;
                    }
                }
            }

            if (sb.Length == 0)
            {
                return "⚠️ No scan summary found in output.";
            }

            return sb.ToString().TrimEnd();
        }

        private void startupBtn_Click(object sender, EventArgs e)
        {
            try
            {
                string appName = "AMSI-Detector-Monitor";
                string appPath = $"\"{Application.ExecutablePath}\" --background";

                RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                if (rk == null)
                {
                    MessageBox.Show("Unable to access registry to modify startup settings.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                bool isCurrentlyEnabled = rk.GetValue(appName) != null;

                if (!isCurrentlyEnabled)
                {
                    // Enable startup
                    rk.SetValue(appName, appPath);

                    // Ask if user wants to start monitoring now
                    var result = MessageBox.Show(
                        "✅ AMSI background monitoring has been enabled to start with Windows.\n\n" +
                        "Would you like to start background monitoring now?",
                        "Startup Enabled",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Information);

                    if (result == DialogResult.Yes)
                    {
                        StartBackgroundMonitoringNow();
                    }
                }
                else
                {
                    // Disable startup
                    rk.DeleteValue(appName, false);
                    MessageBox.Show("🛑 AMSI background monitoring has been disabled from Windows startup.",
                        "Startup Disabled", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to modify startup setting:\n" + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartBackgroundMonitoringNow()
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    Arguments = "--background",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                System.Diagnostics.Process.Start(startInfo);

                MessageBox.Show(
                    "🚀 Background monitoring started!\n\n" +
                    "Check your system tray for the AMSI monitor icon. " +
                    "You can now close this window safely.",
                    "Background Monitor Started",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start background monitoring: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

    }
}
