using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SyScan.Desktop.Scanner;

namespace SyScan.Desktop.Views;

public partial class ActiveScanView : UserControl
{
    private readonly string[] _modules;
    private readonly ObservableCollection<ModuleStatusItem> _moduleItems = new();
    private CancellationTokenSource? _cts;

    public ActiveScanView(string[] modules)
    {
        InitializeComponent();
        _modules = modules;
        ModuleStatusList.ItemsSource = _moduleItems;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Populate module list with pending state
        foreach (var moduleId in _modules)
        {
            _moduleItems.Add(new ModuleStatusItem
            {
                ModuleId = moduleId,
                DisplayName = FormatModuleName(moduleId),
                Status = "Pending",
                StatusDetail = "Waiting...",
                StatusColor = new SolidColorBrush(Color.FromRgb(74, 85, 104))
            });
        }

        _cts = new CancellationTokenSource();
        await RunScanAsync(_cts.Token);
    }

    private async Task RunScanAsync(CancellationToken ct)
    {
        var api = App.Api!;
        var engine = new ScanEngine(api);
        var completedModules = new List<string>();
        var failedModules = new List<string>();
        int totalFindings = 0;

        for (int i = 0; i < _modules.Length; i++)
        {
            if (ct.IsCancellationRequested) break;

            var moduleId = _modules[i];
            var item = _moduleItems.FirstOrDefault(m => m.ModuleId == moduleId);
            if (item is null) continue;

            // Update UI
            UpdateModuleStatus(item, "Running", "In progress...",
                new SolidColorBrush(Color.FromRgb(79, 142, 247)));
            CurrentModuleText.Text = $"Running: {FormatModuleName(moduleId)}";
            UpdateProgress(i, _modules.Length);

            // Report to backend
            await api.ReportModuleStartAsync(moduleId);

            // Execute the module
            var result = await engine.RunModuleAsync(moduleId, ct);
            totalFindings += result.FindingsCount;

            if (result.Success)
            {
                completedModules.Add(moduleId);
                UpdateModuleStatus(item, "Done", $"{result.FindingsCount} finding(s)",
                    new SolidColorBrush(Color.FromRgb(76, 175, 130)));
                await api.ReportModuleCompleteAsync(moduleId, result.FindingsCount);
            }
            else if (result.Status == "Unavailable")
            {
                completedModules.Add(moduleId);
                UpdateModuleStatus(item, "N/A", result.ErrorMessage ?? "Unavailable",
                    new SolidColorBrush(Color.FromRgb(74, 85, 104)));
                await api.ReportModuleCompleteAsync(moduleId, 0, "Unavailable", result.ErrorMessage);
            }
            else
            {
                failedModules.Add(moduleId);
                UpdateModuleStatus(item, "Failed", result.ErrorMessage ?? "Error",
                    new SolidColorBrush(Color.FromRgb(224, 88, 88)));
                await api.ReportModuleCompleteAsync(moduleId, 0, "Failed", result.ErrorMessage);
            }
        }

        if (!ct.IsCancellationRequested)
        {
            UpdateProgress(_modules.Length, _modules.Length);
            CurrentModuleText.Text = "Scan complete. Submitting evidence...";
            await api.CompleteScanAsync(totalFindings,
                [.. completedModules], [.. failedModules],
                engine.DiscoveredFilesCount, engine.DiscoveredFilesCount);

            // Navigate to completed view
            Application.Current.Dispatcher.Invoke(() =>
            {
                ((ContentControl)Application.Current.MainWindow.FindName("MainContent")).Content =
                    new CompletedScanView(totalFindings, completedModules.Count, failedModules.Count);
            });
        }
    }

    private void UpdateModuleStatus(ModuleStatusItem item, string status, string detail, SolidColorBrush color)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            item.Status = status;
            item.StatusDetail = detail;
            item.StatusColor = color;
        });
    }

    private void UpdateProgress(int completed, int total)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var pct = total > 0 ? (double)completed / total * 100 : 0;
            OverallProgress.Value = pct;
            ProgressPercentText.Text = $" — {(int)pct}%";
        });
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show("Are you sure you want to cancel the scan?",
            "Cancel Scan", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result == MessageBoxResult.Yes)
        {
            _cts?.Cancel();
            Application.Current.Shutdown();
        }
    }

    private static string FormatModuleName(string moduleId) => moduleId switch
    {
        "process-scanner" => "Running Process Scanner",
        "service-scanner" => "Windows Service Scanner",
        "driver-scanner" => "Kernel Driver Scanner",
        "game-directory" => "Game Directory Scanner",
        "game-log-analyzer" => "Game Log Analyzer",
        "file-system-scanner" => "Full File System Scanner",
        "forensic-artifacts" => "Windows Forensic Artifacts",
        "installed-apps" => "Installed Application Scanner",
        "registry-scanner" => "Windows Registry Scanner",
        "event-log-scanner" => "Windows Event Log Scanner",
        "file-deletion" => "Deleted File Investigation",
        "anti-forensic" => "Anti-Forensic Investigation",
        _ => moduleId
    };
}

public class ModuleStatusItem : System.ComponentModel.INotifyPropertyChanged
{
    private string _status = "Pending";
    private string _statusDetail = "";
    private SolidColorBrush _statusColor = new(Color.FromRgb(74, 85, 104));

    public string ModuleId { get; set; } = "";
    public string DisplayName { get; set; } = "";

    public string Status
    {
        get => _status;
        set { _status = value; OnPropertyChanged(); }
    }
    public string StatusDetail
    {
        get => _statusDetail;
        set { _statusDetail = value; OnPropertyChanged(); }
    }
    public SolidColorBrush StatusColor
    {
        get => _statusColor;
        set { _statusColor = value; OnPropertyChanged(); }
    }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
}

