using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Services;

public class AuditService : IAuditService
{
    private readonly SyScanDbContext _db;

    public AuditService(SyScanDbContext db) => _db = db;

    public async Task LogAsync(string action, Guid? userId = null, Guid? organizationId = null,
        string? entityType = null, string? entityId = null, string? details = null, string? ipAddress = null)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            OrganizationId = organizationId,
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            Details = details,
            IpAddress = ipAddress,
            OccurredAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}

