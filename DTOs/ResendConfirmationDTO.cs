namespace ApiAutenticacao.DTOs
{
    public class ResendConfirmationDTO
    {   
        [Required(ErrorMessage = "O campo 'Email' é obrigatório.")]
        public required string Email { get; set; }
    }
}
