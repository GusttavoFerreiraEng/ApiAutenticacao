using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography; 
using Microsoft.IdentityModel.Tokens;
using Models; 

namespace ApiAutenticacao.Services 
{
    public class AuthService
    {
        private readonly AppDbContext _context;

        private readonly string __jwtKey;

        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            __jwtKey = configuration["jwt:Key"] ?? throw new InvalidOperationException("A chave JWT não foi encontrada no arquivo de configuração.");
        }

        public void Registrar(RegisterDTO registerDto)
        {
            var existingUser = _context.Users.FirstOrDefault(u => u.Email == registerDto.Email);
            if (existingUser != null)
            {
                throw new Exception("Email já cadastrado.");
            }

            var user = new User
            {
                Email = registerDto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password)
            };
            _context.Users.Add(user);
            _context.SaveChanges();
        }

        public (string AccessToken, string RefreshToken) Login(LoginDTO loginDto)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == loginDto.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                throw new Exception("Email ou senha inválidos.");
            }

            var jwt = GerarJwt(user);
            var refreshToken = GerarRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); 
            _context.SaveChanges();

            return (jwt, refreshToken); 
        }

        public (string AccessToken, string RefreshToken) RenovarToken(string refreshTokenAntigo)
        {
            var user = _context.Users.FirstOrDefault(u => u.RefreshToken == refreshTokenAntigo);
            
            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                throw new Exception("Chave inválida ou expirada. Faça login novamente.");
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshToken = GerarRefreshToken();

            user.RefreshToken = novoRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            _context.SaveChanges();

            return (novoJwt, novoRefreshToken);
        }

        public void PromoverParaAdmin(string email)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == email);
            if (user == null)
            {
                throw new Exception("Usuário não encontrado.");
            }

            user.Role = "Admin"; 
            _context.SaveChanges();
        }

        private string GerarJwt(User user)
        {
            var chaveBytes = Encoding.UTF8.GetBytes(__jwtKey);
            var chaveCriptografica = new SymmetricSecurityKey(chaveBytes);
            var credenciais = new SigningCredentials(chaveCriptografica, SecurityAlgorithms.HmacSha256);

            var informacoes = new[] 
            { 
              new Claim(ClaimTypes.Email, user.Email),
              new Claim(ClaimTypes.Role, user.Role)     
            };

            var tokenObjeto = new JwtSecurityToken(
                claims: informacoes, 
                expires: DateTime.UtcNow.AddMinutes(15), 
                signingCredentials: credenciais
            );

            var impressora = new JwtSecurityTokenHandler();
            return impressora.WriteToken(tokenObjeto);
        }

        private string GerarRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}