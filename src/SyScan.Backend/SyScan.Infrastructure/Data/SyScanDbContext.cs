using Microsoft.EntityFrameworkCore;
using SyScan.Core.Entities;

namespace SyScan.Infrastructure.Data;

public class SyScanDbContext : DbContext
{
    public SyScanDbContext(DbContextOptions<SyScanDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMember> OrganizationMembers => Set<OrganizationMember>();
    public DbSet<ScanSession> ScanSessions => Set<ScanSession>();
    public DbSet<ScanInvitation> ScanInvitations => Set<ScanInvitation>();
    public DbSet<ScanConfiguration> ScanConfigurations => Set<ScanConfiguration>();
    public DbSet<ScanEvent> ScanEvents => Set<ScanEvent>();
    public DbSet<ScanFinding> ScanFindings => Set<ScanFinding>();
    public DbSet<EvidenceRecord> EvidenceRecords => Set<EvidenceRecord>();
    public DbSet<ConsentRecord> ConsentRecords => Set<ConsentRecord>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<DetectionRuleVersion> DetectionRuleVersions => Set<DetectionRuleVersion>();
    public DbSet<ScanReport> ScanReports => Set<ScanReport>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User
        modelBuilder.Entity<User>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.Email).IsRequired().HasMaxLength(256);
            e.Property(u => u.DisplayName).IsRequired().HasMaxLength(128);
        });

        // Organization
        modelBuilder.Entity<Organization>(e =>
        {
            e.HasIndex(o => o.Slug).IsUnique();
            e.Property(o => o.Name).IsRequired().HasMaxLength(256);
            e.Property(o => o.Slug).IsRequired().HasMaxLength(64);
        });

        // OrganizationMember — unique per org+user
        modelBuilder.Entity<OrganizationMember>(e =>
        {
            e.HasIndex(m => new { m.OrganizationId, m.UserId }).IsUnique();
            e.HasOne(m => m.Organization).WithMany(o => o.Members).HasForeignKey(m => m.OrganizationId);
            e.HasOne(m => m.User).WithMany(u => u.OrganizationMemberships).HasForeignKey(m => m.UserId);
        });

        // ScanSession
        modelBuilder.Entity<ScanSession>(e =>
        {
            e.HasIndex(s => s.ScanId).IsUnique();
            e.Property(s => s.ScanId).IsRequired().HasMaxLength(16);
            e.Property(s => s.ParticipantLabel).IsRequired().HasMaxLength(256);
            e.Property(s => s.GameId).IsRequired().HasMaxLength(64);
            e.HasOne(s => s.Organization).WithMany(o => o.ScanSessions).HasForeignKey(s => s.OrganizationId);
        });

        // ScanInvitation
        modelBuilder.Entity<ScanInvitation>(e =>
        {
            e.HasIndex(i => i.TokenPrefix);
            e.HasOne(i => i.ScanSession).WithOne(s => s.Invitation).HasForeignKey<ScanInvitation>(i => i.ScanSessionId);
        });

        // ScanConfiguration
        modelBuilder.Entity<ScanConfiguration>(e =>
        {
            e.HasOne(c => c.ScanSession).WithOne(s => s.Configuration).HasForeignKey<ScanConfiguration>(c => c.ScanSessionId);
            if (Database.IsNpgsql())
            {
                e.Property(c => c.EnabledModules).HasColumnType("jsonb");
                e.Property(c => c.ModuleSettings).HasColumnType("jsonb");
            }
        });

        // ScanEvent
        modelBuilder.Entity<ScanEvent>(e =>
        {
            e.HasOne(ev => ev.ScanSession).WithMany(s => s.Events).HasForeignKey(ev => ev.ScanSessionId);
            e.Property(ev => ev.Message).IsRequired().HasMaxLength(1024);
        });

        // ScanFinding
        modelBuilder.Entity<ScanFinding>(e =>
        {
            e.HasOne(f => f.ScanSession).WithMany(s => s.Findings).HasForeignKey(f => f.ScanSessionId);
            e.HasOne(f => f.DetectionRule).WithMany(d => d.Findings).HasForeignKey(f => f.DetectionRuleId).IsRequired(false);
        });

        // EvidenceRecord
        modelBuilder.Entity<EvidenceRecord>(e =>
        {
            e.HasOne(r => r.ScanSession).WithMany(s => s.EvidenceRecords).HasForeignKey(r => r.ScanSessionId);
        });

        // ConsentRecord
        modelBuilder.Entity<ConsentRecord>(e =>
        {
            e.HasOne(c => c.ScanSession).WithMany(s => s.ConsentRecords).HasForeignKey(c => c.ScanSessionId);
        });

        // ScanReport
        modelBuilder.Entity<ScanReport>(e =>
        {
            e.HasOne(r => r.ScanSession).WithOne(s => s.Report).HasForeignKey<ScanReport>(r => r.ScanSessionId);
        });

        // DetectionRule
        modelBuilder.Entity<DetectionRule>(e =>
        {
            e.HasIndex(d => d.RuleId).IsUnique();
            e.Property(d => d.RuleId).IsRequired().HasMaxLength(32);
        });

        // DetectionRuleVersion
        modelBuilder.Entity<DetectionRuleVersion>(e =>
        {
            e.HasIndex(v => new { v.DetectionRuleId, v.Version }).IsUnique();
            e.HasOne(v => v.DetectionRule).WithMany(d => d.Versions).HasForeignKey(v => v.DetectionRuleId);
        });

        // AuditLog
        modelBuilder.Entity<AuditLog>(e =>
        {
            e.HasOne(a => a.User).WithMany(u => u.AuditLogs).HasForeignKey(a => a.UserId).IsRequired(false);
            e.Property(a => a.Action).IsRequired().HasMaxLength(256);
        });
    }

    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return base.SaveChangesAsync(cancellationToken);
    }

    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.Entity is BaseEntity && e.State is EntityState.Modified);

        foreach (var entry in entries)
            ((BaseEntity)entry.Entity).UpdatedAt = DateTime.UtcNow;
    }
}

