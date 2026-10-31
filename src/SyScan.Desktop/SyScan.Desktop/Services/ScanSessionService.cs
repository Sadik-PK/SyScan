using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SyScan.Desktop.Services;

/// <summary>Holds current scan session state shared across all views.</summary>
public class ScanSessionService : INotifyPropertyChanged
{
    private readonly ApiClient _api;

    public ScanSessionService(ApiClient api) => _api = api;

    public string? InvitationToken { get; private set; }
    public string? ScanId { get; private set; }
    public string? OrganizationName { get; private set; }
    public string? GameId { get; private set; }
    public string? ParticipantLabel { get; private set; }
    public string[] EnabledModules { get; private set; } = [];
    public string? ConfigurationHash { get; private set; }
    public bool IsConnected { get; private set; }

    private string _status = "Idle";
    public string Status
    {
        get => _status;
        set { _status = value; OnPropertyChanged(); }
    }

    public async Task<bool> ValidateAndLoadInvitationAsync(string token)
    {
        InvitationToken = token;
        var info = await _api.ValidateInvitationAsync(token);
        if (info is null) return false;

        ScanId = info.ScanId;
        OrganizationName = info.OrganizationName;
        GameId = info.GameId;
        ParticipantLabel = info.ParticipantLabel;
        EnabledModules = info.EnabledModules;
        OnPropertyChanged(nameof(ScanId));
        return true;
    }

    public async Task<bool> PairAsync()
    {
        if (InvitationToken is null) return false;
        var result = await _api.PairInvitationAsync(InvitationToken);
        if (result is null) return false;

        _api.SetSessionToken(result.SessionToken);
        IsConnected = true;
        Status = "Connected";
        return true;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

