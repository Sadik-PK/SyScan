using System.Windows;
using SyScan.Desktop.Services;

namespace SyScan.Desktop;

public partial class App : Application
{
    public static ScanSessionService? ScanSession { get; private set; }
    public static ApiClient? Api { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        Api = new ApiClient("https://localhost:7001");
        ScanSession = new ScanSessionService(Api);

        // Check for invitation token passed via command-line or custom URI scheme
        string? token = null;
        if (e.Args.Length > 0)
            token = ExtractToken(e.Args[0]);

        var mainWindow = new MainWindow(token);
        mainWindow.Show();
    }

    private static string? ExtractToken(string arg)
    {
        // Support: syscan://invite/TOKEN or just the raw TOKEN
        if (arg.StartsWith("syscan://invite/", StringComparison.OrdinalIgnoreCase))
            return arg["syscan://invite/".Length..];
        if (arg.StartsWith("--invite=", StringComparison.OrdinalIgnoreCase))
            return arg["--invite=".Length..];
        // Raw token
        if (arg.Length > 10 && !arg.StartsWith("-"))
            return arg;
        return null;
    }
}
