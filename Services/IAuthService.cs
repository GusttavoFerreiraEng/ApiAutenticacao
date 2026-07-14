using Models;

namespace ApiAutenticacao.Services
{
    public interface IAuthService
    {
        Task RegistrarAsync(RegisterDTO registerDto);
        Task<(string AccessToken, string RefreshToken)> LoginAsync(LoginDTO loginDto);
        Task<(string AccessToken, string RefreshToken)> RenovarTokenAsync(string refreshTokenAntigo);
        Task PromoverParaAdminAsync(string email);
        Task<object?> ObterPerfilAsync(string email); // Retorna object temporariamente até criarmos um DTO de Perfil
        Task InvalidarRefreshTokenAsync(string refreshToken);
    }
}