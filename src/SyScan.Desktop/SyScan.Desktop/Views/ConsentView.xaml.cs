using System.Windows;
using System.Windows.Controls;

namespace SyScan.Desktop.Views;

public partial class ConsentView : UserControl
{
    public ConsentView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        var session = App.ScanSession!;
        ScanIdLabel.Text = session.ScanId;
        OrgLabel.Text = session.OrganizationName;
        GameLabel.Text = session.GameId;
        ParticipantLabel.Text = session.ParticipantLabel;

        // Display human-readable module names
        ModulesList.ItemsSource = session.EnabledModules
            .Select(FormatModuleName)
            .ToList();
    }

    private async void ApproveButton_Click(object sender, RoutedEventArgs e)
    {
        ApproveButton.IsEnabled = false;
        ApproveButton.Content = "Starting...";

        // Record consent with the backend
        var session = App.ScanSession!;
        var configHash = ComputeConfigHash(session.EnabledModules);
        var success = await App.Api!.RecordConsentAsync(true, configHash);

        if (!success)
        {
            ApproveButton.IsEnabled = true;
            ApproveButton.Content = "Approve & Start Scan";
            MessageBox.Show("Failed to record consent. Please try again.",
                "Connection Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Navigate to active scanning view
        var scanView = new ActiveScanView(session.EnabledModules);
        ((ContentControl)Application.Current.MainWindow.FindName("MainContent")).Content = scanView;
    }

    private void DeclineButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to decline this scan? The administrator will be notified.",
            "Decline Scan", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        _ = App.Api!.RecordConsentAsync(false, string.Empty, "Participant declined.");
        Application.Current.Shutdown();
    }

    private static string ComputeConfigHash(string[] modules)
    {
        var sorted = modules.OrderBy(m => m);
        var json = System.Text.Json.JsonSerializer.Serialize(sorted);
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string FormatModuleName(string moduleId) => moduleId switch
    {
        "process-scanner" => "Running Process Scanner",
        "service-scanner" => "Windows Service Scanner",
        "driver-scanner" => "Kernel Driver Scanner",
        "game-directory" => "Game Directory Scanner",
        "game-log-analyzer" => "Game Log Analyzer",
        "file-system-scanner" => "Full File System Scanner",
        "forensic-artifacts" => "Windows Forensic Artifacts (Prefetch, Amcache, USN Journal)",
        "installed-apps" => "Installed Application Scanner",
        "registry-scanner" => "Windows Registry Scanner",
        "event-log-scanner" => "Windows Event Log Scanner",
        "file-deletion" => "Deleted File Investigation",
        "anti-forensic" => "Anti-Forensic Investigation",
        _ => moduleId
    };
}

