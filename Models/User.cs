using System;

namespace Models
{
    public class User
    {

        public int Id { get; set; } 
        
        public required string Email { get; set; }
        
        public required string PasswordHash { get; set; }
 
        public string Role { get; set; } = "User"; 


        public string? RefreshTokenHash { get; set; }
        

        public DateTimeOffset? RefreshTokenExpiryTime { get; set; } 

        public int AccessFailedCount { get; set; } = 0;
        public DateTimeOffset? LockoutEnd { get; set; }
    }
}