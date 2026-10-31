using SyScan.Core.Entities;

namespace SyScan.Api.Services;

public interface IAuditService
{
    Task LogAsync(string action, Guid? userId = null, Guid? organizationId = null,
        string? entityType = null, string? entityId = null, string? details = null, string? ipAddress = null);
}

