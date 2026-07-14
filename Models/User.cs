using System;

namespace Models
{
    public class User
    {
        // 1. Chave única consolidada (padrão EF Core).
        public int Id { get; set; } 
        
        public required string Email { get; set; }
        
        public required string PasswordHash { get; set; }
        
        // Padrão bom de inicialização
        public string Role { get; set; } = "User"; 

        // 2. Hash em vez do token em si
        public string? RefreshTokenHash { get; set; }
        
        // 3. DateTimeOffset no lugar de DateTime. Vital para migração PostgreSQL/Nuvem.
        public DateTimeOffset? RefreshTokenExpiryTime { get; set; } 
    }
}