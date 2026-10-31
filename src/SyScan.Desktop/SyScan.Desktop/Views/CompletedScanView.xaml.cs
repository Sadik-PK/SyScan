using System.Windows;
using System.Windows.Controls;

namespace SyScan.Desktop.Views;

public partial class CompletedScanView : UserControl
{
    public CompletedScanView(int findingsCount, int completedCount, int failedCount)
    {
        InitializeComponent();
        FindingsCountText.Text = findingsCount.ToString();
        CompletedText.Text = completedCount.ToString();
        FailedText.Text = failedCount.ToString();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Application.Current.Shutdown();
    }
}
