using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SyScan.Api.Services;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;
using Xunit;

namespace SyScan.Tests;

public class InvitationServiceTests
{
    private static (SyScanDbContext db, IScanService scanService, IInvitationService inviteService) CreateServices()
    {
        var options = new DbContextOptionsBuilder<SyScanDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        var db = new SyScanDbContext(options);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"] = "TEST_SECRET_KEY_FOR_TESTS_AT_LEAST_32_BYTES_LONG",
                ["Jwt:Issuer"] = "syscan-api",
                ["Jwt:Audience"] = "syscan-web",
                ["Jwt:ExpiryMinutes"] = "60"
            })
            .Build();

        var broadcaster = new TestScanEventBroadcaster();
        var scanService = new ScanService(db, config, broadcaster);
        var auditService = new AuditService(db);
        var inviteService = new InvitationService(db, scanService, auditService);

        return (db, scanService, inviteService);
    }

    [Fact]
    public async Task CreateInvitation_GeneratesHashedSingleUseToken()
    {
        var (db, scanService, inviteService) = CreateServices();

        var org = new Organization { Name = "Test Org", Slug = "test-org" };
        var user = new User { Email = "investigator@syscan.internal", DisplayName = "Investigator" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("Player1", "minecraft", "default", ["process-scanner"]),
            user.Id, org.Id);

        var (invitation, rawToken) = await inviteService.CreateInvitationAsync(scan.Id, 60);

        Assert.NotNull(rawToken);
        Assert.True(rawToken.Length >= 32);
        Assert.False(invitation.IsUsed);
        Assert.NotEqual(rawToken, invitation.TokenHash); // Token is hashed, never stored plaintext
        Assert.Equal(rawToken[..8], invitation.TokenPrefix);
    }

    [Fact]
    public async Task ValidateInvitation_ValidToken_ReturnsScanDetails()
    {
        var (db, scanService, inviteService) = CreateServices();

        var org = new Organization { Name = "Acme Esports", Slug = "acme" };
        var user = new User { Email = "admin@acme.com", DisplayName = "Admin" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("CompetitorA", "fivem", "full", ["process-scanner", "service-scanner"]),
            user.Id, org.Id);

        var (_, rawToken) = await inviteService.CreateInvitationAsync(scan.Id, 30);

        var result = await inviteService.ValidateInvitationAsync(rawToken);

        Assert.True(result.IsValid);
        Assert.Equal(scan.ScanId, result.ScanId);
        Assert.Equal("Acme Esports", result.OrganizationName);
        Assert.Equal("CompetitorA", result.ParticipantLabel);
        Assert.Equal("fivem", result.GameId);
    }

    [Fact]
    public async Task PairInvitation_SingleUse_SecondPairFails()
    {
        var (db, scanService, inviteService) = CreateServices();

        var org = new Organization { Name = "Test Org", Slug = "test-org" };
        var user = new User { Email = "admin@test.com", DisplayName = "Admin" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("PlayerX", "minecraft", "default", ["process-scanner"]),
            user.Id, org.Id);

        var (_, rawToken) = await inviteService.CreateInvitationAsync(scan.Id, 60);

        // First pairing succeeds
        var pair1 = await inviteService.PairInvitationAsync(rawToken, "192.168.1.100");
        Assert.True(pair1.Success);
        Assert.NotNull(pair1.SessionToken);
        Assert.Equal(scan.ScanId, pair1.ScanId);

        // Second pairing with same token MUST fail (single-use credential protection)
        var pair2 = await inviteService.PairInvitationAsync(rawToken, "192.168.1.101");
        Assert.False(pair2.Success);
        Assert.Contains("already used", pair2.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateInvitation_ExpiredToken_ReturnsError()
    {
        var (db, scanService, inviteService) = CreateServices();

        var org = new Organization { Name = "Test Org", Slug = "test-org" };
        var user = new User { Email = "admin@test.com", DisplayName = "Admin" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("PlayerX", "minecraft", "default", ["process-scanner"]),
            user.Id, org.Id);

        // Expired 10 minutes ago
        var (_, rawToken) = await inviteService.CreateInvitationAsync(scan.Id, -10);

        var result = await inviteService.ValidateInvitationAsync(rawToken);
        Assert.False(result.IsValid);
        Assert.Contains("expired", result.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }
}

public class TestScanEventBroadcaster : IScanEventBroadcaster
{
    public List<(string scanId, ScanEventType eventType, string message)> BroadcastEvents { get; } = [];

    public Task BroadcastEventAsync(string scanId, ScanEventType eventType, string message, object? payload = null)
    {
        BroadcastEvents.Add((scanId, eventType, message));
        return Task.CompletedTask;
    }

    public Task BroadcastFindingAsync(string scanId, ScanFinding finding) => Task.CompletedTask;
    public Task BroadcastModuleProgressAsync(string scanId, string moduleId, string status, int progressPercent) => Task.CompletedTask;
    public Task BroadcastStatusChangeAsync(string scanId, ScanStatus newStatus) => Task.CompletedTask;
}

