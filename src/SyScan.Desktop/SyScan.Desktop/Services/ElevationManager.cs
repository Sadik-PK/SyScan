using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using SyScan.Scanner.IPC;

namespace SyScan.Desktop.Services;

public static class ElevationManager
{
    public static CollectorIpcClient? CollectorClient { get; private set; }
    public static bool IsElevated { get; private set; }
    public static string ElevationStatusMessage { get; private set; } = "Initializing...";
    public static string SessionNonce { get; private set; } = string.Empty;
    public static Process? CollectorProcess { get; private set; }

    public static async Task InitializeElevationAsync()
    {
        // Check if current desktop process is already running as Administrator
        bool currentProcAdmin = false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            currentProcAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { }

        // Generate cryptographically secure random session nonce
        byte[] nonceBytes = new byte[16];
        RandomNumberGenerator.Fill(nonceBytes);
        SessionNonce = Convert.ToHexStringLower(nonceBytes);

        // Find SyScan.Collector.exe
        string baseDir = AppContext.BaseDirectory;
        string collectorPath = Path.Combine(baseDir, "SyScan.Collector.exe");

        // In dev environment, check relative build paths if not in output dir
        if (!File.Exists(collectorPath))
        {
            string devPath = Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\SyScan.Collector\bin\Debug\net10.0-windows\win-x64\SyScan.Collector.exe"));
            if (File.Exists(devPath))
                collectorPath = devPath;
        }

        if (!File.Exists(collectorPath))
        {
            IsElevated = currentProcAdmin;
            ElevationStatusMessage = currentProcAdmin
                ? "Running with built-in administrator privileges."
                : "Elevated collector binary not found. Running in limited user-level mode.";
            return;
        }

        // Trigger UAC elevation prompt immediately via runas
        var psi = new ProcessStartInfo
        {
            FileName = collectorPath,
            Arguments = $"--pipe-nonce={SessionNonce} --parent-pid={Process.GetCurrentProcess().Id}",
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden
        };

        try
        {
            CollectorProcess = Process.Start(psi);
            if (CollectorProcess != null)
            {
                // Connect to the secure named pipe
                string pipeName = $"SyScan_Collector_{SessionNonce}";
                var client = new CollectorIpcClient(pipeName, SessionNonce);

                bool connected = await client.ConnectAsync(timeoutMs: 4000);
                if (connected)
                {
                    CollectorClient = client;
                    IsElevated = true;
                    ElevationStatusMessage = "Administrator privileges granted. Deep forensic collector active.";
                    return;
                }
            }

            IsElevated = false;
            ElevationStatusMessage = "Failed to establish secure IPC with elevated collector. User-level mode active.";
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED (User clicked 'No' on UAC)
        {
            IsElevated = false;
            ElevationStatusMessage = "Administrator elevation was declined by participant. Proceeding in limited user-level mode.";
        }
        catch (Exception ex)
        {
            IsElevated = false;
            ElevationStatusMessage = $"Elevation unavailable ({ex.Message}). Proceeding in user-level mode.";
        }
    }

    public static async Task ShutdownAsync()
    {
        if (CollectorClient != null)
        {
            try
            {
                await CollectorClient.SendRequestAsync(new CollectorRequest
                {
                    Command = IpcCommands.Shutdown,
                    SessionNonce = SessionNonce
                });
            }
            catch { }

            CollectorClient.Dispose();
            CollectorClient = null;
        }

        if (CollectorProcess != null && !CollectorProcess.HasExited)
        {
            try
            {
                CollectorProcess.Kill();
            }
            catch { }
        }
    }
}

