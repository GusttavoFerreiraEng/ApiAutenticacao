using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ApiAutenticacao.Services;
using Microsoft.AspNetCore.RateLimiting;
using FluentValidation;

[ApiController]
[EnableRateLimiting("LoginRateLimit")]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly AuthService _authService; 
    private readonly IValidator<RegisterDTO> _registerValidator;

    // Agora o Controller pede o Serviço de Autenticação
    public AuthController(AuthService authService, AppDbContext context, IValidator<RegisterDTO> registerValidator)
    {
        _authService = authService;
        _context = context;
        _registerValidator = registerValidator;
    }


[HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDTO registerDto)
    {
        var validationResult = _registerValidator.Validate(registerDto);
        if (!validationResult.IsValid)
        {
            return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));
        }

        try
        {
            _authService.Registrar(registerDto); 
            return Ok("Usuário cadastrado com sucesso.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message); 
        }
    }

[HttpPost("login")]
public IActionResult Login([FromBody] LoginDTO loginDto)
{
    try
    {
        var tokenPronto = _authService.Login(loginDto); 
        
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true, 
            Secure = true,  
            SameSite = SameSiteMode.Strict, 
            Expires = DateTime.Now.AddHours(2) 
        };

        Response.Cookies.Append("jwt", tokenPronto, cookieOptions);

        return Ok(new { Mensagem = "Login realizado! Token guardado." });
    }
    catch (Exception ex)
    {
        return Unauthorized(ex.Message);
    }
}

[HttpPost("logout")]
public IActionResult Logout()
{
    Response.Cookies.Delete("jwt");
    
    return Ok(new { Mensagem = "Você saiu do sistema!" });
}

[HttpPost("promover/{email}")]
public IActionResult Promover(string email)
{
    try
    {
        _authService.PromoverParaAdmin(email);
        return Ok($"O usuário {email} agora é o Chefe!");
    }
    catch (Exception ex)
    {
        return BadRequest(ex.Message);
    }
}
[Authorize]
[HttpGet("perfil")]
public IActionResult MeuPerfil()   
    {
        var emailUser = User.FindFirst(ClaimTypes.Email)?.Value;
        var userLog = _context.Users.FirstOrDefault(u => u.Email == emailUser);

        if (userLog == null)
        {
            return NotFound("Usuário não encontrado.");
        }

        return Ok(new 
        {
            Mensage = "Bem-vindo!",
            SeuId = userLog.Id,
            SeuEmail = userLog.Email
        });
    }

[Authorize(Roles = "Admin")]
[HttpGet("admin")]
public IActionResult AdminOnly()
    {
        return Ok("Bem-vindo, Admin!.");
    }

}
