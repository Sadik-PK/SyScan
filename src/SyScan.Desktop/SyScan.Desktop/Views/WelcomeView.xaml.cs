using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace SyScan.Desktop.Views;

public partial class WelcomeView : UserControl
{
    public WelcomeView()
    {
        InitializeComponent();
    }

    private void VerifyButton_Click(object sender, RoutedEventArgs e)
    {
        var raw = TokenInput.Text.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            ShowError("Please paste your invitation token or URL.");
            return;
        }

        // Extract token from URL if needed
        var token = ExtractToken(raw);
        if (string.IsNullOrEmpty(token))
        {
            ShowError("The invitation appears to be invalid. Please check and try again.");
            return;
        }

        ErrorText.Visibility = Visibility.Collapsed;
        VerifyButton.IsEnabled = false;
        VerifyButton.Content = "Verifying...";

        // Navigate to verification view
        var nav = (SyScan.Desktop.Services.NavigationService?)
            Application.Current.MainWindow?.FindName("MainContent");
        var mainWindow = Application.Current.MainWindow as MainWindow;
        if (mainWindow is not null)
        {
            // We need to navigate — get the navigation service from app
            var verificationView = new InvitationVerificationView(token);
            ((ContentControl)mainWindow.FindName("MainContent")).Content = verificationView;
        }
    }

    private void TokenInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) VerifyButton_Click(sender, e);
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private static string? ExtractToken(string input)
    {
        // Handle full URL: https://syscan.example/invite/TOKEN
        if (input.Contains("/invite/"))
        {
            var idx = input.IndexOf("/invite/") + "/invite/".Length;
            return input[idx..].Split('?')[0].Trim();
        }
        // Handle syscan:// URI
        if (input.StartsWith("syscan://invite/", StringComparison.OrdinalIgnoreCase))
            return input["syscan://invite/".Length..];
        // Raw token
        return input.Length > 8 ? input : null;
    }
}

