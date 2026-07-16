namespace ApiAutenticacao.DTOs

{
    public class UserProfileResponseDTO
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string SecurityStamp { get; set; } = string.Empty; 
    }
}