using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SyScan.Infrastructure.Data;
using Xunit;

namespace SyScan.Tests;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _dbName = "syscan_test_" + Guid.NewGuid().ToString("N");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("DatabaseProvider", "InMemory");
        builder.UseSetting("InMemoryDbName", _dbName);
        builder.UseEnvironment("Testing");
    }
}

public class ApiIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    public ApiIntegrationTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsOk()
    {
        var response = await _client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        Assert.True(json.TryGetProperty("status", out var status));
        Assert.Equal("Healthy", status.GetString());
    }

    [Fact]
    public async Task CompleteEndToEndScanLifecycle_Succeeds()
    {
        // 1. Admin Registers
        var regResponse = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            email = "tournament.admin@syscan.internal",
            password = "SecurePassword123!",
            displayName = "Tournament Admin"
        });
        Assert.Equal(HttpStatusCode.OK, regResponse.StatusCode);
        var regJson = await regResponse.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        var adminToken = regJson.GetProperty("token").GetString()!;
        Assert.NotEmpty(adminToken);

        // 2. Admin creates a scan
        var scanReq = new HttpRequestMessage(HttpMethod.Post, "/api/scans");
        scanReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        scanReq.Content = JsonContent.Create(new
        {
            participantLabel = "Player_Zero",
            gameId = "minecraft",
            scanProfileId = "standard",
            enabledModules = new[] { "process-scanner", "service-scanner" },
            invitationExpiryMinutes = 60
        });

        var scanResponse = await _client.SendAsync(scanReq);
        Assert.Equal(HttpStatusCode.Created, scanResponse.StatusCode);
        var scanCreated = await scanResponse.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        var scanId = scanCreated.GetProperty("scanId").GetString()!;
        var invitationToken = scanCreated.GetProperty("invitationToken").GetString()!;

        Assert.StartsWith("SS-", scanId);
        Assert.NotEmpty(invitationToken);

        // 3. Participant opens invitation (public endpoint, no auth required)
        var inviteResponse = await _client.GetAsync($"/api/invite/{invitationToken}");
        Assert.Equal(HttpStatusCode.OK, inviteResponse.StatusCode);
        var inviteDetails = await inviteResponse.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        Assert.Equal(scanId, inviteDetails.GetProperty("scanId").GetString());
        Assert.Equal("Player_Zero", inviteDetails.GetProperty("participantLabel").GetString());

        // 4. Desktop app pairs with the invitation
        var pairResponse = await _client.PostAsync($"/api/invite/{invitationToken}/pair", null);
        Assert.Equal(HttpStatusCode.OK, pairResponse.StatusCode);
        var pairResult = await pairResponse.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        var scannerToken = pairResult.GetProperty("sessionToken").GetString()!;
        Assert.NotEmpty(scannerToken);

        // 5. Desktop app records participant consent
        var consentReq = new HttpRequestMessage(HttpMethod.Post, "/api/scanner/consent");
        consentReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scannerToken);
        // Note: For test simplicity, compute config hash for ["process-scanner", "service-scanner"]
        var jsonModules = JsonSerializer.Serialize(new[] { "process-scanner", "service-scanner" }.OrderBy(m => m));
        var configHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(jsonModules))).ToLowerInvariant();
        consentReq.Content = JsonContent.Create(new
        {
            approved = true,
            configurationHash = configHash
        });

        var consentResponse = await _client.SendAsync(consentReq);
        Assert.Equal(HttpStatusCode.OK, consentResponse.StatusCode);

        // 6. Scanner starts module and submits finding
        var modStartReq = new HttpRequestMessage(HttpMethod.Post, "/api/scanner/modules/process-scanner/start");
        modStartReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scannerToken);
        var modStartResp = await _client.SendAsync(modStartReq);
        Assert.Equal(HttpStatusCode.OK, modStartResp.StatusCode);

        var findingReq = new HttpRequestMessage(HttpMethod.Post, "/api/scanner/findings");
        findingReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scannerToken);
        findingReq.Content = JsonContent.Create(new
        {
            moduleId = "process-scanner",
            category = "Detection",
            severity = "Critical",
            title = "Known Cheat Process: cheatengine-x86_64.exe",
            description = "Active memory editor process detected.",
            filePath = "C:\\Tools\\cheatengine.exe",
            confidence = 95,
            explanation = "Signature matched active process table."
        });
        var findingResp = await _client.SendAsync(findingReq);
        Assert.Equal(HttpStatusCode.OK, findingResp.StatusCode);

        // 7. Scanner completes module and completes scan
        var modCompleteReq = new HttpRequestMessage(HttpMethod.Post, "/api/scanner/modules/process-scanner/complete");
        modCompleteReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scannerToken);
        modCompleteReq.Content = JsonContent.Create(new
        {
            status = "Completed",
            findingsCount = 1
        });
        var modCompleteResp = await _client.SendAsync(modCompleteReq);
        Assert.Equal(HttpStatusCode.OK, modCompleteResp.StatusCode);

        var scanCompleteReq = new HttpRequestMessage(HttpMethod.Post, "/api/scanner/complete");
        scanCompleteReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scannerToken);
        scanCompleteReq.Content = JsonContent.Create(new
        {
            totalFindings = 1,
            completedModules = new[] { "process-scanner" },
            failedModules = Array.Empty<string>()
        });
        var scanCompleteResp = await _client.SendAsync(scanCompleteReq);
        Assert.Equal(HttpStatusCode.OK, scanCompleteResp.StatusCode);

        // 8. Admin retrieves full forensic report
        var reportReq = new HttpRequestMessage(HttpMethod.Get, $"/api/scans/{scanId}/report");
        reportReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var reportResp = await _client.SendAsync(reportReq);
        Assert.Equal(HttpStatusCode.OK, reportResp.StatusCode);

        var reportJson = await reportResp.Content.ReadFromJsonAsync<JsonElement>(JsonOpts);
        Assert.Equal(scanId, reportJson.GetProperty("scanId").GetString());
        Assert.Equal("Completed", reportJson.GetProperty("status").GetString());
        var summary = reportJson.GetProperty("summary");
        Assert.Equal(1, summary.GetProperty("totalFindings").GetInt32());
        Assert.Equal(1, summary.GetProperty("critical").GetInt32());
    }
}
