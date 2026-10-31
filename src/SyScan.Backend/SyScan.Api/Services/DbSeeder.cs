using Microsoft.EntityFrameworkCore;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Services;

public static class DbSeeder
{
    public static async Task SeedAsync(SyScanDbContext db, ILogger logger)
    {
        try
        {
            if (!await db.Users.AnyAsync())
            {
                logger.LogInformation("Seeding initial administrator and organization...");

                var org = new Organization
                {
                    Name = "SyScan Security Operations",
                    Slug = "syscan-sec",
                    IsActive = true
                };
                db.Organizations.Add(org);

                var adminUser = new User
                {
                    Email = "admin@syscan.internal",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("AdminPassword123!"),
                    DisplayName = "Lead Investigator",
                    IsActive = true
                };
                db.Users.Add(adminUser);

                var membership = new OrganizationMember
                {
                    Organization = org,
                    User = adminUser,
                    Role = OrganizationRole.SuperAdmin,
                    IsActive = true
                };
                db.OrganizationMembers.Add(membership);

                // Seed some detection rules
                var rules = new[]
                {
                    new DetectionRule
                    {
                        RuleId = "DET-001",
                        Name = "Known Memory Editor Process",
                        Description = "Detects active memory injection or debugging tools such as Cheat Engine.",
                        Severity = FindingSeverity.Critical,
                        DefaultConfidence = 95,
                        RuleType = "ProcessName",
                        RuleContent = "cheatengine,x64dbg,kiddions"
                    },
                    new DetectionRule
                    {
                        RuleId = "DET-002",
                        Name = "Vulnerable Signed Kernel Driver",
                        Description = "Detects driver files abused for kernel memory read/write.",
                        Severity = FindingSeverity.Critical,
                        DefaultConfidence = 90,
                        RuleType = "DriverFileName",
                        RuleContent = "gdrv.sys,capcom.sys,procexp.sys"
                    },
                    new DetectionRule
                    {
                        RuleId = "DET-003",
                        Name = "Windows Event Log Cleared",
                        Description = "Detects anti-forensic log wipe events (Event ID 1102 / 104).",
                        Severity = FindingSeverity.Critical,
                        DefaultConfidence = 95,
                        RuleType = "EventId",
                        RuleContent = "1102,104"
                    }
                };
                db.DetectionRules.AddRange(rules);

                await db.SaveChangesAsync();
                logger.LogInformation("Database seeded successfully with default admin 'admin@syscan.internal'");
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not seed database. PostgreSQL might not be running or initialized yet.");
        }
    }
}
