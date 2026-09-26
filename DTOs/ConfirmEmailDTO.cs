namespace ApiAutenticacao.DTOs
{
    public class ConfirmEmailDTO
    {   
        [Required(ErrorMessage = "O campo 'Email' é obrigatório.")]
        public required string Email { get; set; }
        [Required(ErrorMessage = "O campo 'Code' é obrigatório.")]
        public required string Code { get; set; }
    }
}
