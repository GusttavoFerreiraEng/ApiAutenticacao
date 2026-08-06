using System;
using System.Collections.Generic;

namespace Models
{

    public class User : BaseEntity
    {
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
        public string Role { get; set; } = "User"; 

        public int AccessFailedCount { get; set; } = 0;
        public DateTimeOffset? LockoutEnd { get; set; }
        public string? PasswordResetToken { get; set; }
        public DateTimeOffset? ResetTokenExpires { get; set; }
        public string SecurityStamp { get; set; } = Guid.NewGuid().ToString();
        public DateTimeOffset? DeletedAt { get; set; }
        public bool EmailConfirmed { get; set; } = false;
        public string? EmailConfirmationToken { get; set; }
        public DateTimeOffset? EmailConfirmationTokenExpires { get; set; }
        public byte[]? RowVersion { get; set; }

        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }

}