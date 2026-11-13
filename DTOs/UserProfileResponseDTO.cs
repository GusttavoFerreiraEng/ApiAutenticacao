namespace ApiAutenticacao.DTOs

{
    public class UserProfileResponseDTO
    {   
        public long Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public bool HasPassword { get; set; }
    }
}
