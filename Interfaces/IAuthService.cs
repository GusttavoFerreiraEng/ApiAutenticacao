using Models;
using ApiAutenticacao.Common;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Interfaces
{
    public interface IAuthService
    {
        Task<Result> RegistrarAsync(RegisterDTO registerDto, CancellationToken cancellationToken = default);
        Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto, CancellationToken cancellationToken = default);
        Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo, CancellationToken cancellationToken = default);
        Task<Result> PromoverParaAdminAsync(string email, CancellationToken cancellationToken = default);
        Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email, CancellationToken cancellationToken = default);
        Task<Result> InvalidarRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

        Task<Result<string>> SolicitarRecuperacaoSenhaAsync(string email, CancellationToken cancellationToken = default);
        
        Task<Result> RedefinirSenhaAsync(ResetPasswordDTO resetDto, CancellationToken cancellationToken = default);
    }
}