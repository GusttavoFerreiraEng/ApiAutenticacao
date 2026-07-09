using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;
using Models;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;

    public AuthController(AppDbContext context)
    {
        _context = context;
    }


[HttpPost("register")]
public IActionResult Register([FromBody] RegisterDTO registerDto)
{
    var existingUser = _context.Users.FirstOrDefault(u => u.Email == registerDto.Email);
    if (existingUser != null)
    {
        return BadRequest("Email já cadastrado.");
    }
    // Cria um novo usuário com o email e a senha fornecidos
    var user = new User
    {
        Email = registerDto.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password)
    };
    _context.Users.Add(user);
    _context.SaveChanges();
    return Ok("Usuário cadastrado com sucesso.");
}

[HttpPost("login")]
public IActionResult Login([FromBody] LoginDTO loginDto)
{
    //Verifica se o usuário existe e se a senha está correta
    var user = _context.Users.FirstOrDefault(u => u.Email == loginDto.Email);
    if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
    {
        return Unauthorized("Email ou senha inválidos.");
    }

    var chaveTexto = "MinhaSuperChaveSecretaDoEstagiario123"; // No mínimo 16 caracteres
    var chaveBytes = Encoding.UTF8.GetBytes(chaveTexto);
    var chaveCriptografica = new SymmetricSecurityKey(chaveBytes);
    var credenciais = new SigningCredentials(chaveCriptografica, SecurityAlgorithms.HmacSha256);

    var informacoes = new[] { new Claim("email", user.Email) };

    var tokenObjeto = new JwtSecurityToken(
        claims: informacoes, 
        expires: DateTime.Now.AddHours(2), 
        signingCredentials: credenciais
    );

    var impressora = new JwtSecurityTokenHandler();
    var tokenPronto = impressora.WriteToken(tokenObjeto);

    return Ok(new { Token = tokenPronto });
}
}