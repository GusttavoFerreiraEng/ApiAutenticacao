using Models;
using ApiAutenticacao.DTOs;
using ApiAutenticacao.common;

namespace ApiAutenticacao.Services
{
    public interface IAuthService
    {
        Task<Result> RegistrarAsync(RegisterDTO registerDto);
        Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto);
        Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo);
        Task<Result> PromoverParaAdminAsync(string email);
        Task<Result<UserProfileResponseDTO?>>  ObterPerfilAsync(string email); // Retorna object temporariamente até criarmos um DTO de Perfil
        Task<Result> InvalidarRefreshTokenAsync(string refreshToken);
    }
}