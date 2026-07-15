using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Models;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.common;

namespace ApiAutenticacao.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUnitOfWork _uow;
        private readonly IConfiguration _configuration;
        private readonly string _jwtKey;

        public AuthService(IUnitOfWork uow, IConfiguration configuration)
        {
            _uow = uow;
            _configuration = configuration;
            _jwtKey = configuration["jwt:Key"] ?? throw new InvalidOperationException("Chave JWT não configurada.");
        }

        public async Task<Result> RegistrarAsync(RegisterDTO registerDto)
        {
            var existingUser = await _uow.Users.GetByEmailAsync(registerDto.Email);
            if (existingUser != null)
            {
                return Result.Failure(AuthErrors.EmailAlreadyExists);
            }

            var user = new User
            {
                Email = registerDto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)
            };

            await _uow.Users.AddAsync(user);
            await _uow.CommitAsync();

            return Result.Success();
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto)
        {
            var user = await _uow.Users.GetByEmailAsync(loginDto.Email);

            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            var jwt = GerarJwt(user);
            var refreshToken = GerarRefreshToken();

            user.RefreshTokenHash = ComputeSha256Hash(refreshToken);
            
            // CORREÇÃO: Usando DateTimeOffset
            user.RefreshTokenExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _uow.CommitAsync();

            return Result<(string, string)>.Success((jwt, refreshToken));
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo)
        {
            var providedHash = ComputeSha256Hash(refreshTokenAntigo);
            var user = await _uow.Users.GetByRefreshTokenHashAsync(providedHash);

            // CORREÇÃO: Comparando com DateTimeOffset
            if (user == null || user.RefreshTokenExpiryTime <= DateTimeOffset.UtcNow)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshToken = GerarRefreshToken();

            user.RefreshTokenHash = ComputeSha256Hash(novoRefreshToken);
            
            // CORREÇÃO: Usando DateTimeOffset
            user.RefreshTokenExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _uow.CommitAsync();

            return Result<(string, string)>.Success((novoJwt, novoRefreshToken));
        }

        public async Task<Result> PromoverParaAdminAsync(string email)
        {
            var user = await _uow.Users.GetByEmailAsync(email);
            if (user == null)
            {
                return Result.Failure(AuthErrors.UserNotFound);
            }

            user.Role = "Admin";
            await _uow.CommitAsync();
            return Result.Success();
        }

        public async Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email)
        {
            var user = await _uow.Users.GetByEmailAsync(email);
            if (user == null) return Result<UserProfileResponseDTO?>.Failure(AuthErrors.UserNotFound);

            var perfilDto = new UserProfileResponseDTO(user.Id, user.Email, user.Role);

            return Result<UserProfileResponseDTO?>.Success(perfilDto);
        }

        // CORREÇÃO: Assinatura atualizada para retornar Result
        public async Task<Result> InvalidarRefreshTokenAsync(string refreshToken)
        {
            var hash = ComputeSha256Hash(refreshToken);
            var user = await _uow.Users.GetByRefreshTokenHashAsync(hash);

            if (user != null)
            {
                user.RefreshTokenHash = null; 
                user.RefreshTokenExpiryTime = null;
                await _uow.CommitAsync();
            }

            return Result.Success(); // CORREÇÃO: Agora retorna sucesso
        }

        private string GerarJwt(User user)
        {
            var chaveBytes = Encoding.UTF8.GetBytes(_jwtKey);
            var credenciais = new SigningCredentials(new SymmetricSecurityKey(chaveBytes), SecurityAlgorithms.HmacSha256);

            var informacoes = new[]
            {
              new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), 
              new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),        
              new Claim(ClaimTypes.Email, user.Email),
              new Claim(ClaimTypes.Role, user.Role)
            };

            var tokenObjeto = new JwtSecurityToken(
                issuer: _configuration["jwt:Issuer"],   
                audience: _configuration["jwt:Audience"], 
                claims: informacoes,
                expires: DateTime.UtcNow.AddMinutes(15), // Para o JWT, DateTime padrão está correto
                signingCredentials: credenciais
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenObjeto);
        }

        private string GerarRefreshToken()
        {
            var randomNumber = new byte[64]; 
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private static string ComputeSha256Hash(string rawData)
        {
            using var sha256Hash = SHA256.Create();
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return Convert.ToBase64String(bytes);
        }

        Task<Result> IAuthService.RegistrarAsync(RegisterDTO registerDto)
        {
            throw new NotImplementedException();
        }

        Task<Result<(string AccessToken, string RefreshToken)>> IAuthService.LoginAsync(LoginDTO loginDto)
        {
            throw new NotImplementedException();
        }

        Task<Result<(string AccessToken, string RefreshToken)>> IAuthService.RenovarTokenAsync(string refreshTokenAntigo)
        {
            throw new NotImplementedException();
        }

        Task<Result> IAuthService.PromoverParaAdminAsync(string email)
        {
            throw new NotImplementedException();
        }

        Task<Result<UserProfileResponseDTO?>> IAuthService.ObterPerfilAsync(string email)
        {
            throw new NotImplementedException();
        }

        Task<Result> IAuthService.InvalidarRefreshTokenAsync(string refreshToken)
        {
            throw new NotImplementedException();
        }
    }
}