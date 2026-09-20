namespace ApiAutenticacao.DTOs
{
    public class ChangePasswordDTO
    {
        public string SenhaAtual { get; set; } = string.Empty;
        public string NovaSenha { get; set; } = string.Empty;
    }
}