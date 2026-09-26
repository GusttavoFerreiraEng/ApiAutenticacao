using System;

namespace Models
{
    public class RefreshToken : BaseEntity
    {  // Representa um token de atualização (refresh token) associado a um usuário.
        public required string TokenHash { get; set; } 
        public DateTimeOffset ExpiryTime { get; set; }
        
        public string? PreviousTokenHash { get; set; }
        public DateTimeOffset? PreviousTokenGraceExpiry { get; set; }

        public long UserId { get; set; }
        public User User { get; set; } = null!;
    }
}