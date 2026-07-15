using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using ApiAutenticacao.DTOs;
using ApiAutenticacao.common;
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
        private readonly IAuthService _authService;
        private readonly IValidator<RegisterDTO> _registerValidator;
        private readonly IValidator<LoginDTO> _loginValidator;
        private readonly ILogger<AuthController> _logger;

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
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto)
        {
            var validationResult = await _registerValidator.ValidateAsync(registerDto);
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

            var result = await _authService.LoginAsync(loginDto);

            if (result.ISFailure)
            {
                var (jwt, refreshToken) = result.Value;
                SetTokenCookies(jwt, refreshToken);

                return Ok(new MessageResponseDTO("Login realizado com sucesso!"));
            }

            if (result.Error == AuthErrors.InvalidCredentials)
            {
                return Unauthorized(new { Erro = result.Error.Description });
            }

            return BadRequest(new { Erro = result.Error.Description });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            var refreshTokenAntigo = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshTokenAntigo))
                return Unauthorized(new MessageResponseDTO("Sessão expirada. Faça login novamente."));

            var result = await _authService.RenovarTokenAsync(refreshTokenAntigo);

            if (result.ISFailure)
            {
                _logger.LogWarning("Tentativa de refresh token falhou: {Erro}", result.Error.Description);
                ClearTokenCookies(); // Regra de segurança mantida
                return Unauthorized(new MessageResponseDTO(result.Error.Description));
            }

            var (novoJwt, novoRefreshToken) = result.Value;

            SetTokenCookies(novoJwt, novoRefreshToken);

            return Ok(new MessageResponseDTO("Tokens renovados com sucesso!"));
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
            var emailUser = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(emailUser)) return Unauthorized();

            var result = await _authService.ObterPerfilAsync(emailUser);

            if (result.ISFailure)
            {
                if (result.Error == AuthErrors.UserNotFound)
                {
                    ClearTokenCookies(); // Regra de segurança: se o user não existe mais no DB, limpa os cookies
                    return NotFound(new { Erro = result.Error.Description });
                }
                return BadRequest(new { Erro = result.Error.Description });
            }

            return Ok(result.Value);
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