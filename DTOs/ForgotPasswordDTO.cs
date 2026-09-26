namespace ApiAutenticacao.DTOs
{
    public class ForgotPasswordDTO
    {   
        [Required(ErrorMessage = "O campo 'Email' é obrigatório.")]
        public string Email { get; set; } = string.Empty;
        
    }
}