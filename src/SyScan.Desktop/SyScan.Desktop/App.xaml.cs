using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using SyScan.Desktop.Services;

namespace SyScan.Desktop;

public partial class App : Application
{
    public static ScanSessionService? ScanSession { get; private set; }
    public static ApiClient? Api { get; private set; }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        string apiUrl = Environment.GetEnvironmentVariable("SYSCAN_API_URL") ?? "http://localhost:5000";
        Api = new ApiClient(apiUrl);
        ScanSession = new ScanSessionService(Api);

        // Register syscan:// URI scheme in HKCU for seamless browser launching
        RegisterUriScheme();

        // ADDITIONAL REQUIREMENT 1: Request administrator elevation immediately upon application launch
        await ElevationManager.InitializeElevationAsync();

        // Check for invitation token passed via command-line or custom URI scheme
        string? token = null;
        if (e.Args.Length > 0)
            token = ExtractToken(e.Args[0]);

        var mainWindow = new MainWindow(token);
        mainWindow.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        await ElevationManager.ShutdownAsync();
        base.OnExit(e);
    }

    private static void RegisterUriScheme()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ??
                             Path.Combine(AppContext.BaseDirectory, "SyScan.exe");

            using var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\syscan");
            if (key != null)
            {
                key.SetValue("", "URL:SyScan Protocol");
                key.SetValue("URL Protocol", "");

                using var cmdKey = key.CreateSubKey(@"shell\open\command");
                if (cmdKey != null)
                {
                    cmdKey.SetValue("", $"\"{exePath}\" \"%1\"");
                }
            }
        }
        catch
        {
            // Non-critical if user environment prevents HKCU write
        }
    }

    private static string? ExtractToken(string arg)
    {
        if (arg.StartsWith("syscan://invite/", StringComparison.OrdinalIgnoreCase))
            return arg["syscan://invite/".Length..].TrimEnd('/');
        if (arg.StartsWith("syscan://invite?token=", StringComparison.OrdinalIgnoreCase))
            return arg["syscan://invite?token=".Length..].TrimEnd('/');
        if (arg.StartsWith("--invite=", StringComparison.OrdinalIgnoreCase))
            return arg["--invite=".Length..];
        if (arg.Length > 10 && !arg.StartsWith("-"))
            return arg;
        return null;
    }
}
