using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Models;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Common;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;

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

        public async Task<Result> RegistrarAsync(RegisterDTO registerDto, CancellationToken cancellationToken = default)
        {
            var existingUser = await _uow.Users.GetByEmailAsync(registerDto.Email, cancellationToken);
            if (existingUser != null)
            {
                return Result.Failure(AuthErrors.EmailAlreadyExists);
            }

            var user = new User
            {
                Email = registerDto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)
            };

            await _uow.Users.AddAsync(user, cancellationToken);
            await _uow.CommitAsync(cancellationToken);

            return Result.Success();
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(loginDto.Email, cancellationToken);

            if (user == null)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
            {
                return Result<(string, string)>.Failure(AuthErrors.AccountLocked);
            }

            if (!BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 5)
                {
                    user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
                }
                await _uow.CommitAsync(cancellationToken);
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            user.AccessFailedCount = 0;
            user.LockoutEnd = null;

            var jwt = GerarJwt(user);
            var refreshToken = GerarRefreshToken();

            user.RefreshTokenHash = ComputeSha256Hash(refreshToken);
            user.RefreshTokenExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _uow.CommitAsync(cancellationToken);

            return Result<(string, string)>.Success((jwt, refreshToken));
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo, CancellationToken cancellationToken = default)
        {
            var providedHash = ComputeSha256Hash(refreshTokenAntigo);
            var user = await _uow.Users.GetByRefreshTokenHashAsync(providedHash, cancellationToken);

            if (user == null || user.RefreshTokenExpiryTime <= DateTimeOffset.UtcNow)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshToken = GerarRefreshToken();

            user.PreviousRefreshTokenHash = user.RefreshTokenHash;
            user.PreviousTokenGraceExpiry = DateTimeOffset.UtcNow.AddMinutes(1);

            user.RefreshTokenHash = ComputeSha256Hash(novoRefreshToken);
            user.RefreshTokenExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _uow.CommitAsync(cancellationToken);

            return Result<(string, string)>.Success((novoJwt, novoRefreshToken));
        }

        public async Task<Result> PromoverParaAdminAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(email, cancellationToken);
            if (user == null)
            {
                return Result.Failure(AuthErrors.UserNotFound);
            }

            user.Role = "Admin";
            await _uow.CommitAsync(cancellationToken);
            return Result.Success();
        }

        public async Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(email, cancellationToken);

            if (user == null)
                return Result<UserProfileResponseDTO?>.Failure(AuthErrors.UserNotFound);

            var profile = new UserProfileResponseDTO
            {
                Id = user.Id,
                Email = user.Email,
                Role = user.Role,
                SecurityStamp = user.SecurityStamp
            };

            return Result<UserProfileResponseDTO?>.Success(profile);
        }

        public async Task<Result> InvalidarRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var hash = ComputeSha256Hash(refreshToken);
            var user = await _uow.Users.GetByRefreshTokenHashAsync(hash, cancellationToken);

            if (user != null)
            {
                user.RefreshTokenHash = null;
                user.RefreshTokenExpiryTime = null;
                await _uow.CommitAsync(cancellationToken);
            }

            return Result.Success();
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
              new Claim(ClaimTypes.Role, user.Role),
              new Claim("SecurityStamp", user.SecurityStamp)
            };

            var tokenObjeto = new JwtSecurityToken(
                issuer: _configuration["jwt:Issuer"],
                audience: _configuration["jwt:Audience"],
                claims: informacoes,
                expires: DateTime.UtcNow.AddMinutes(15), 
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
    }
}