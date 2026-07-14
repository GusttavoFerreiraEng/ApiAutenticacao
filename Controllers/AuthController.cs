using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ApiAutenticacao.Services;
using Microsoft.AspNetCore.RateLimiting;
using FluentValidation;
using Models;

namespace ApiAutenticacao.Controllers
{
    [ApiController]
    [EnableRateLimiting("LoginRateLimit")]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        // 1. Removido o AppDbContext e a __jwtKey. Dependemos apenas do Service (Abstração).
        private readonly IAuthService _authService; 
        private readonly IValidator<RegisterDTO> _registerValidator;
        private readonly IValidator<LoginDTO> _loginValidator;
        private readonly ILogger<AuthController> _logger; // Adicionado para observabilidade

        public AuthController(
            IAuthService authService, 
            IValidator<RegisterDTO> registerValidator, 
            IValidator<LoginDTO> loginValidator,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _registerValidator = registerValidator;
            _loginValidator = loginValidator;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto) // async Task
        {
            var validationResult = await _registerValidator.ValidateAsync(registerDto); // Validação assíncrona
            if (!validationResult.IsValid)
            {
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));
            }

            try
            {
                await _authService.RegistrarAsync(registerDto); 
                return Ok(new { Mensagem = "Usuário cadastrado com sucesso." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no registro do email {Email}", registerDto.Email);
                // Evitamos expor detalhes internos. Retornamos mensagem genérica.
                return BadRequest(new { Erro = "Não foi possível concluir o cadastro. Verifique os dados e tente novamente." }); 
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            var validationResult = await _loginValidator.ValidateAsync(loginDto);
            if (!validationResult.IsValid)
            {
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));
            }
            
            try
            {
                var (jwt, refreshToken) = await _authService.LoginAsync(loginDto); 
                
                SetTokenCookies(jwt, refreshToken); // Extraído para manter código limpo (DRY)

                return Ok(new { Mensagem = "Login realizado!" });
            }
            catch (UnauthorizedAccessException) // Criar exceções customizadas no domínio é ideal
            {
                // Erro genérico para evitar User Enumeration
                return Unauthorized(new { Erro = "E-mail ou senha incorretos." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro inesperado no login do e-mail {Email}", loginDto.Email);
                return StatusCode(500, new { Erro = "Ocorreu um erro interno." });
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            try
            {
                var refreshTokenAntigo = Request.Cookies["refreshToken"];
                
                if (string.IsNullOrEmpty(refreshTokenAntigo))
                    return Unauthorized(new { Erro = "Sessão expirada. Faça login novamente." });

                var (novoJwt, novoRefreshToken) = await _authService.RenovarTokenAsync(refreshTokenAntigo);

                SetTokenCookies(novoJwt, novoRefreshToken);

                return Ok(new { Mensagem = "Tokens renovados com sucesso!" });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Tentativa de refresh token inválida");
                // Sempre limpar cookies se der erro no refresh para forçar novo login
                ClearTokenCookies();
                return Unauthorized(new { Erro = "Falha na renovação da sessão." });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            
            if (!string.IsNullOrEmpty(refreshToken))
            {
                // Delegamos a invalidação no banco para o serviço, e não validamos o JWT no banco
                await _authService.InvalidarRefreshTokenAsync(refreshToken);
            }    

            ClearTokenCookies();
            
            return Ok(new { Mensagem = "Você saiu do sistema!" });
        }
        
        [Authorize(Roles = "Admin")]
        [HttpPost("promover/{email}")]
        public async Task<IActionResult> Promover(string email)
        {
            // Ponto de melhoria: receber via [FromBody] e validar o e-mail, pois via URL pode vazar em logs de proxy/rede.
            try
            {
                await _authService.PromoverParaAdminAsync(email);
                return Ok(new { Mensagem = $"O usuário {email} foi promovido." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao promover usuário {Email}", email);
                return BadRequest(new { Erro = "Não foi possível concluir a ação." });
            }
        }

        [Authorize]
        [HttpGet("perfil")]
        public async Task<IActionResult> MeuPerfil()   
        {
            // User.FindFirst(ClaimTypes.NameIdentifier) (Id) é mais rápido para buscas no DB do que Email
            var emailUser = User.FindFirst(ClaimTypes.Email)?.Value;
            
            if (string.IsNullOrEmpty(emailUser))
                return Unauthorized();

            // Lógica delegada ao serviço. Controller apenas orquestra o HTTP.
            var userLog = await _authService.ObterPerfilAsync(emailUser);

            if (userLog == null)
            {
                ClearTokenCookies();
                return NotFound(new { Erro = "Usuário não encontrado." });
            }

            return Ok(userLog); // userLog já deve ser um DTO de resposta, não a Entidade User completa
        }

        // --- Helper Methods ---
        private void SetTokenCookies(string jwt, string refreshToken)
        {
            Response.Cookies.Append("jwt", jwt, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddMinutes(15) });
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(7) });
        }

        private void ClearTokenCookies()
        {
            Response.Cookies.Delete("jwt");
            Response.Cookies.Delete("refreshToken");
        }
    }
}