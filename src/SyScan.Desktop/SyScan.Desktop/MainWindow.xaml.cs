using System.Windows;
using SyScan.Desktop.Services;
using SyScan.Desktop.Views;

namespace SyScan.Desktop;

public partial class MainWindow : Window
{
    private readonly NavigationService _navigation;

    public MainWindow(string? invitationToken = null)
    {
        InitializeComponent();
        _navigation = new NavigationService(MainContent);

        if (!string.IsNullOrEmpty(invitationToken))
            _navigation.NavigateTo(new InvitationVerificationView(invitationToken));
        else
            _navigation.NavigateTo(new WelcomeView());
    }
}
