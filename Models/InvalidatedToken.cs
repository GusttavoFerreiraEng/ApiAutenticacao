using System;

namespace Models
{
    public class InvalidatedToken
    {
        public int Id { get; set; }
        public required string Token { get; set; }
        public DateTime ExpirationDate { get; set; } 
    }
}