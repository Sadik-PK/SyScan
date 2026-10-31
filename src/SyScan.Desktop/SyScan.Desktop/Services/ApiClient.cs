using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace SyScan.Desktop.Services;

public class ApiClient
{
    private readonly HttpClient _http;
    private string? _sessionToken;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public ApiClient(string baseUrl)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl) };
    }

    public void SetSessionToken(string token)
    {
        _sessionToken = token;
        _http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    public async Task<InvitationInfo?> ValidateInvitationAsync(string token)
    {
        try
        {
            var response = await _http.GetAsync($"api/invite/{token}");
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadFromJsonAsync<InvitationInfo>(JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public async Task<PairResult?> PairInvitationAsync(string token)
    {
        try
        {
            var response = await _http.PostAsync($"api/invite/{token}/pair", null);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadFromJsonAsync<PairResult>(JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public async Task<bool> RecordConsentAsync(bool approved, string configurationHash, string? declineReason = null)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("api/scanner/consent", new
            {
                approved,
                configurationHash,
                declineReason
            });
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ReportModuleStartAsync(string moduleId)
    {
        try
        {
            var response = await _http.PostAsync($"api/scanner/modules/{moduleId}/start", null);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ReportModuleCompleteAsync(string moduleId, int findingsCount, string status = "Completed", string? error = null)
    {
        try
        {
            var response = await _http.PostAsJsonAsync($"api/scanner/modules/{moduleId}/complete", new
            {
                status,
                findingsCount,
                errorMessage = error
            });
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<string?> SubmitFindingAsync(object finding)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("api/scanner/findings", finding);
            if (!response.IsSuccessStatusCode) return null;
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            return result.GetProperty("findingId").GetString();
        }
        catch { return null; }
    }

    public async Task<bool> CompleteScanAsync(int totalFindings, string[] completedModules, string[] failedModules)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("api/scanner/complete", new
            {
                totalFindings,
                completedModules,
                failedModules
            });
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }
}

public record InvitationInfo(
    string ScanId,
    string OrganizationName,
    string GameId,
    string ParticipantLabel,
    string[] EnabledModules);

public record PairResult(string SessionToken, string ScanId);

