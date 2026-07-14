using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using Models;
using ApiAutenticacao.Data;

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

        public async Task RegistrarAsync(RegisterDTO registerDto)
        {
            // Assíncrono para liberar thread
            var existingUser = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == registerDto.Email);
            if (existingUser != null)
            {
                throw new InvalidOperationException("Email já cadastrado."); // Ideal é uma DomainException
            }

            var user = new User
            {
                Email = registerDto.Email,
                // WorkFactor (custo) 11: padrão atual recomendado de segurança e performance
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
        }

        public async Task<(string AccessToken, string RefreshToken)> LoginAsync(LoginDTO loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == loginDto.Email);
            
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                // Uma exceção de autorização genérica capturada no controller
                throw new UnauthorizedAccessException("Credenciais inválidas."); 
            }

            var jwt = GerarJwt(user);
            var refreshToken = GerarRefreshToken();

            user.RefreshTokenHash = ComputeSha256Hash(refreshToken); // Usando hash simples em vez de HMAC
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // Prox passo: levar para IOptions
            
            await _context.SaveChangesAsync();

            return (jwt, refreshToken);
        }

        public async Task<(string AccessToken, string RefreshToken)> RenovarTokenAsync(string refreshTokenAntigo)
        {   
            var providedHash = ComputeSha256Hash(refreshTokenAntigo);
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshTokenHash == providedHash);
            
            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                throw new UnauthorizedAccessException("Refresh token inválido ou expirado.");
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshToken = GerarRefreshToken();

            // Rotação de Refresh Token
            user.RefreshTokenHash = ComputeSha256Hash(novoRefreshToken);
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            
            await _context.SaveChangesAsync();

            return (novoJwt, novoRefreshToken);
        }

        public async Task PromoverParaAdminAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                throw new KeyNotFoundException("Usuário não encontrado.");
            }

            user.Role = "Admin"; 
            await _context.SaveChangesAsync();
        }

        public async Task<object?> ObterPerfilAsync(string email)
        {
            var user = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return null;

            return new { SeuId = user.Id, SeuEmail = user.Email }; // Futuramente: retornar um UserResponseDTO
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
                issuer: _configuration["jwt:Issuer"],   // Ex: "MinhaEmpresa.ApiAutenticacao"
                audience: _configuration["jwt:Audience"], // Ex: "MinhaEmpresa.Frontend"
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
    }
}