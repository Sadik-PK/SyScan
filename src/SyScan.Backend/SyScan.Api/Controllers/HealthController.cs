using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Controllers;

[ApiController]
[Route("api/health")]
public class HealthController : ControllerBase
{
    private readonly SyScanDbContext _db;
    private readonly ILogger<HealthController> _logger;

    public HealthController(SyScanDbContext db, ILogger<HealthController> logger)
    {
        _db = db;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetHealth()
    {
        bool dbHealthy = false;
        string? dbError = null;

        try
        {
            dbHealthy = (_db.Database.ProviderName?.Contains("InMemory", StringComparison.OrdinalIgnoreCase) == true)
                        || await _db.Database.CanConnectAsync();
        }
        catch (Exception ex)
        {
            dbError = ex.Message;
            _logger.LogWarning("Database connection test failed: {Message}", ex.Message);
        }

        var status = dbHealthy ? "Healthy" : "Degraded";

        return Ok(new
        {
            status,
            version = "1.0.0",
            service = "SyScan Backend API",
            timestamp = DateTime.UtcNow,
            environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            checks = new
            {
                database = new
                {
                    status = dbHealthy ? "Healthy" : "Unhealthy",
                    provider = "PostgreSQL",
                    error = dbError
                },
                system = new
                {
                    processMemoryMb = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024),
                    os = Environment.OSVersion.VersionString
                }
            }
        });
    }
}
