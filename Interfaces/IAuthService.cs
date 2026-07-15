using Models;
using ApiAutenticacao.Common;

using ApiAutenticacao.common; 
namespace ApiAutenticacao.Interfaces
{
    public interface IAuthService
    {
        Task<Result> RegistrarAsync(RegisterDTO registerDto);
        
        Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto);
        
        Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo);
        
        Task<Result> PromoverParaAdminAsync(string email);
        
        Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email); 
        
        Task<Result> InvalidarRefreshTokenAsync(string refreshToken);
    }
}