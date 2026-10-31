using System.Windows.Controls;

namespace SyScan.Desktop.Services;

/// <summary>Simple navigation service that swaps the content of a ContentControl.</summary>
public class NavigationService
{
    private readonly ContentControl _host;

    public NavigationService(ContentControl host) => _host = host;

    public void NavigateTo(object view) => _host.Content = view;
}

