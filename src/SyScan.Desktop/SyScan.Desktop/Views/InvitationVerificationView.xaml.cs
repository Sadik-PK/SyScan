using System.Windows;
using System.Windows.Controls;

namespace SyScan.Desktop.Views;

public partial class InvitationVerificationView : UserControl
{
    private readonly string _token;

    public InvitationVerificationView(string token)
    {
        InitializeComponent();
        _token = token;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await VerifyInvitationAsync();
    }

    private async Task VerifyInvitationAsync()
    {
        var session = App.ScanSession!;
        var success = await session.ValidateAndLoadInvitationAsync(_token);

        if (!success)
        {
            ShowError("This invitation is invalid, expired, or has already been used.");
            return;
        }

        // Populate details
        ScanIdText.Text = session.ScanId ?? "Unknown";
        OrgText.Text = session.OrganizationName ?? "Unknown Organization";
        GameText.Text = FormatGameId(session.GameId);
        ParticipantText.Text = session.ParticipantLabel ?? "Unknown";

        LoadingPanel.Visibility = Visibility.Collapsed;
        DetailsPanel.Visibility = Visibility.Visible;
    }

    private async void ContinueButton_Click(object sender, RoutedEventArgs e)
    {
        ContinueButton.IsEnabled = false;
        ContinueButton.Content = "Connecting...";

        // Pair — exchange invitation for session token
        var paired = await App.ScanSession!.PairAsync();
        if (!paired)
        {
            ContinueButton.IsEnabled = true;
            ContinueButton.Content = "Continue to Scan Details →";
            MessageBox.Show("Failed to connect to the scan session. Please check your internet connection.",
                "Connection Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Navigate to consent view
        var consentView = new ConsentView();
        ((ContentControl)Application.Current.MainWindow.FindName("MainContent")).Content = consentView;
    }

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        ((ContentControl)Application.Current.MainWindow.FindName("MainContent")).Content = new WelcomeView();
    }

    private void ShowError(string message)
    {
        LoadingPanel.Visibility = Visibility.Collapsed;
        ErrorMessage.Text = message;
        ErrorPanel.Visibility = Visibility.Visible;
    }

    private static string FormatGameId(string? gameId) => gameId?.ToUpperInvariant() switch
    {
        "MINECRAFT" => "Minecraft",
        "FIVEM" => "FiveM / GTA V",
        "ROBLOX" => "Roblox",
        "R6SIEGE" => "Rainbow Six Siege",
        _ => gameId ?? "Unknown Game"
    };
}

