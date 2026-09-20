using System;

namespace Models
{
    public class RefreshToken : BaseEntity
    {
        public required string TokenHash { get; set; } 
        public DateTimeOffset ExpiryTime { get; set; }
        
        public string? PreviousTokenHash { get; set; }
        public DateTimeOffset? PreviousTokenGraceExpiry { get; set; }

        public long UserId { get; set; }
        public User User { get; set; } = null!;
    }
}