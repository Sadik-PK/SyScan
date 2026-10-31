using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SyScan.Api.Services;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;
using Xunit;

namespace SyScan.Tests;

public class ScanSessionTests
{
    private static (SyScanDbContext db, IScanService scanService) CreateScanService()
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
        return (db, scanService);
    }

    [Fact]
    public async Task CreateScan_GeneratesStandardScanId()
    {
        var (db, scanService) = CreateScanService();

        var org = new Organization { Name = "Tournament Org", Slug = "tournament" };
        var user = new User { Email = "referee@tourney.com", DisplayName = "Head Referee" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("PlayerOne", "minecraft", "strict", ["process-scanner", "game-directory"]),
            user.Id, org.Id);

        Assert.NotNull(scan.ScanId);
        Assert.StartsWith("SS-", scan.ScanId);
        Assert.Equal(11, scan.ScanId.Length); // "SS-" + 8 hex chars = 11 chars
        Assert.Equal(ScanStatus.Created, scan.Status);
        Assert.NotNull(scan.Configuration);
        Assert.NotEmpty(scan.Configuration.ConfigurationHash);
    }

    [Fact]
    public async Task CancelScan_SetsStatusToCancelled()
    {
        var (db, scanService) = CreateScanService();

        var org = new Organization { Name = "League Org", Slug = "league" };
        var user = new User { Email = "admin@league.com", DisplayName = "Admin" };
        db.Organizations.Add(org);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var scan = await scanService.CreateScanAsync(
            new CreateScanRequest("PlayerTwo", "fivem", "standard", ["process-scanner"]),
            user.Id, org.Id);

        var cancelled = await scanService.CancelScanAsync(scan.ScanId, user.Id);
        Assert.True(cancelled);

        var updated = await scanService.GetScanAsync(scan.ScanId, org.Id);
        Assert.NotNull(updated);
        Assert.Equal(ScanStatus.Cancelled, updated.Status);
    }
}
