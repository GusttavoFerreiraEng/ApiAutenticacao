using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using Models;
using ApiAutenticacao.Data;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly string _jwtKey;

        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
            _jwtKey = configuration["jwt:Key"] ?? throw new InvalidOperationException("Chave JWT não configurada.");
        }

        public async Task<Result> RegistrarAsync(RegisterDTO registerDto)
        {
            // Assíncrono para liberar thread
            var existingUser = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == registerDto.Email);
            if (existingUser != null)
            {
                return Result.Failure(AuthErrors.EmailAlreadyExists);
            }

            var user = new User
            {
                Email = registerDto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Result.Success();
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == loginDto.Email);

            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            var jwt = GerarJwt(user);
            var refreshToken = GerarRefreshToken();

            user.RefreshTokenHash = ComputeSha256Hash(refreshToken);
            user.RefreshTokenExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _context.SaveChangesAsync();

            return Result<(string, string)>.Success((jwt, refreshToken));
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo)
        {
            var providedHash = ComputeSha256Hash(refreshTokenAntigo);
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshTokenHash == providedHash);

            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshToken = GerarRefreshToken();

            // Rotação de Refresh Token
            user.RefreshTokenHash = ComputeSha256Hash(novoRefreshToken);
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

            await _context.SaveChangesAsync();

            return Result<(string, string)>.Success((novoJwt, novoRefreshToken));
        }

        public async Task<Result> PromoverParaAdminAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                return Result.Failure(AuthErrors.UserNotFound);
            }

            user.Role = "Admin";
            await _context.SaveChangesAsync();
            return Result.Success();
        }

        public async Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email)
        {
            var user = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return Result<UserProfileResponseDTO?>.Failure(AuthErrors.UserNotFound);

            var perfilDto = new UserProfileResponseDTO(user.Id, user.Email, user.Role);

            return Result<UserProfileResponseDTO?>.Success(perfilDto);
        }

        public async Task InvalidarRefreshTokenAsync(string refreshToken)
        {
            var hash = ComputeSha256Hash(refreshToken);
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshTokenHash == hash);

            if (user != null)
            {
                user.RefreshTokenHash = null; // Revogação no banco
                user.RefreshTokenExpiryTime = null;
                await _context.SaveChangesAsync();
            }
        }

        private string GerarJwt(User user)
        {
            var chaveBytes = Encoding.UTF8.GetBytes(_jwtKey);
            var credenciais = new SigningCredentials(new SymmetricSecurityKey(chaveBytes), SecurityAlgorithms.HmacSha256);

            // Adicionando claims vitais para a RFC do JWT
            var informacoes = new[]
            {
              new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID para possível revogação
              new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),        // Subject (Dono do token)
              new Claim(ClaimTypes.Email, user.Email),
              new Claim(ClaimTypes.Role, user.Role)
            };

            var tokenObjeto = new JwtSecurityToken(
                issuer: _configuration["jwt:Issuer"],   // "MinhaEmpresa.ApiAutenticacao"
                audience: _configuration["jwt:Audience"], // "MinhaEmpresa.Frontend"
                claims: informacoes,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: credenciais
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenObjeto);
        }

        private string GerarRefreshToken()
        {
            var randomNumber = new byte[64]; // Aumentado para 64 bytes para mais entropia
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        // Simplificado para SHA256 padrão (sem chave externa) - Suficiente para proteger contra DB leaks.
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