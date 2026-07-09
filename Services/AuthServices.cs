using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Models; 

namespace ApiAutenticacao.Services 
{
    public class AuthService
    {
        private readonly AppDbContext _context;

        public AuthService(AppDbContext context)
        {
            _context = context;
        }

        public void Registrar(RegisterDTO registerDto)
        {
            var existingUser = _context.Users.FirstOrDefault(u => u.Email == registerDto.Email);
            if (existingUser != null)
            {
                // Se der erro,"joga" uma exceção para o Controller capturar
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

        public string Login(LoginDTO loginDto)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == loginDto.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                throw new Exception("Email ou senha inválidos.");
            }

            //JWT
            var chaveTexto = "MinhaSuperChaveSecretaDoEstagiario123"; 
            var chaveBytes = Encoding.UTF8.GetBytes(chaveTexto);
            var chaveCriptografica = new SymmetricSecurityKey(chaveBytes);
            var credenciais = new SigningCredentials(chaveCriptografica, SecurityAlgorithms.HmacSha256);

            var informacoes = new[] 

            { new Claim(ClaimTypes.Email, user.Email),
              new Claim(ClaimTypes.Role, user.Role)     
            };

            var tokenObjeto = new JwtSecurityToken(
                claims: informacoes, 
                expires: DateTime.Now.AddHours(2), 
                signingCredentials: credenciais
            );

            var impressora = new JwtSecurityTokenHandler();
            return impressora.WriteToken(tokenObjeto); 
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
}
}