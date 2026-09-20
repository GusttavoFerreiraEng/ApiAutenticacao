using System.ComponentModel.DataAnnotations;

namespace ApiAutenticacao.DTOs
{
    public class ResetPasswordDTO
    {
        [Required(ErrorMessage = "O e-mail é obrigatório.")]
        [EmailAddress(ErrorMessage = "Formato de e-mail inválido.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "O token de recuperação é obrigatório.")]
        public string Token { get; set; } = string.Empty;

        [Required(ErrorMessage = "A nova senha é obrigatória.")]
        [MinLength(6, ErrorMessage = "A senha deve ter no mínimo 6 caracteres.")]
        public string NovaSenha { get; set; } = string.Empty;
    }
}