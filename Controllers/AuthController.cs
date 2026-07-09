using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ApiAutenticacao.Services;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;
using FluentValidation;
using Models;

[ApiController]
[EnableRateLimiting("LoginRateLimit")]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly AuthService _authService; 
    private readonly IValidator<RegisterDTO> _registerValidator;

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
            var (jwt, refreshToken) = _authService.Login(loginDto); 
            
            var jwtCookieOptions = new CookieOptions
            {
                HttpOnly = true, 
                Secure = true,  
                SameSite = SameSiteMode.Strict, 
                Expires = DateTime.Now.AddMinutes(15) 
            };
            Response.Cookies.Append("jwt", jwt, jwtCookieOptions);

            var refreshCookieOptions = new CookieOptions
            {
                HttpOnly = true, 
                Secure = true,  
                SameSite = SameSiteMode.Strict, 
                Expires = DateTime.Now.AddDays(7) 
            };
            Response.Cookies.Append("refreshToken", refreshToken, refreshCookieOptions);

            return Ok(new { Mensagem = "Login realizado!" });
        }
        catch (Exception ex)
        {
            return Unauthorized(ex.Message);
        }
    }

    [HttpPost("refresh")]
    public IActionResult Refresh()
    {
        try
        {
            var refreshTokenAntigo = Request.Cookies["refreshToken"];
            
            if (string.IsNullOrEmpty(refreshTokenAntigo))
            {
                return Unauthorized("Chave não encontrada. Faça login novamente.");
            }

            var (novoJwt, novoRefreshToken) = _authService.RenovarToken(refreshTokenAntigo);

            var jwtCookieOptions = new CookieOptions
            {
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.Now.AddMinutes(15)
            };
            Response.Cookies.Append("jwt", novoJwt, jwtCookieOptions);

            var refreshCookieOptions = new CookieOptions
            {
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.Now.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", novoRefreshToken, refreshCookieOptions);

            return Ok(new { Mensagem = "Tokens renovados com sucesso!" });
        }
        catch (Exception ex)
        {
            return Unauthorized(ex.Message);
        }
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        var tokenNoCofre = Request.Cookies["jwt"];

        if (!string.IsNullOrEmpty(tokenNoCofre))
        {
            var tokenRevogado = new InvalidatedToken
            {
                Token = tokenNoCofre,
                ExpirationDate = DateTime.Now.AddMinutes(15) // Agora expira em 15 min junto com o token
            };

            _context.InvalidatedTokens.Add(tokenRevogado);
            _context.SaveChanges();
        }    

        Response.Cookies.Delete("jwt");
        Response.Cookies.Delete("refreshToken");
        
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
        return Ok("Bem-vindo, Admin!");
    }
}