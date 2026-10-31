namespace SyScan.Core.Entities;

public enum OrganizationRole
{
    SuperAdmin = 0,
    Admin = 1,
    Moderator = 2,
    Viewer = 3
}

public class OrganizationMember : BaseEntity
{
    public Guid OrganizationId { get; set; }
    public Organization Organization { get; set; } = null!;

    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public OrganizationRole Role { get; set; } = OrganizationRole.Moderator;
    public bool IsActive { get; set; } = true;
}

