namespace ApiAutenticacao.DTOs
{
    public class ChangePasswordDTO
    {  
        [Required(ErrorMessage = "O campo 'SenhaAtual' é obrigatório.")]
        public string SenhaAtual { get; set; } = string.Empty;
        [Required(ErrorMessage = "O campo 'NovaSenha' é obrigatório.")]
        public string NovaSenha { get; set; } = string.Empty;
    }
}