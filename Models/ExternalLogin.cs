namespace Models;

public sealed class ExternalLogin
{
    public long Id { get; set; }
    public required string Provider { get; set; }
    public required string Subject { get; set; }
    public long UserId { get; set; }
    public User User { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
