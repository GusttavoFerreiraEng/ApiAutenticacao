using System;

namespace Models
{
    public class User
    {
        public int UserId { get; set; }
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }

    }
}