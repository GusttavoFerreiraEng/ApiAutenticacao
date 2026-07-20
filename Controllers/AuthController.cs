using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using FluentValidation;
using Models;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;
using ApiAutenticacao.Interfaces;
using Asp.Versioning;

namespace ApiAutenticacao.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [EnableRateLimiting("LoginRateLimit")]
    [Route("api/v1/[controller]")]
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
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto, CancellationToken cancellationToken)
        {
            // O CancellationToken agora otimiza até a validação do FluentValidation
            var validationResult = await _registerValidator.ValidateAsync(registerDto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.RegistrarAsync(registerDto, cancellationToken);
            
            if (result.IsFailure)
                return BadRequest(new MessageResponseDTO(result.Error.Description));

            return Ok(new MessageResponseDTO("Usuário cadastrado com sucesso."));
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto, CancellationToken cancellationToken)
        {
            var validationResult = await _loginValidator.ValidateAsync(loginDto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.LoginAsync(loginDto, cancellationToken);

            if (result.IsFailure)
            {
                // Se a conta estiver bloqueada por excesso de tentativas (Lockout)
                if (result.Error == AuthErrors.AccountLocked)
                    return StatusCode(StatusCodes.Status403Forbidden, new MessageResponseDTO(result.Error.Description));

                if (result.Error == AuthErrors.InvalidCredentials)
                    return Unauthorized(new MessageResponseDTO(result.Error.Description));

                return BadRequest(new MessageResponseDTO(result.Error.Description));
            }

            var (jwt, refreshToken) = result.Value;
            SetTokenCookies(jwt, refreshToken);

            return Ok(new MessageResponseDTO("Login realizado com sucesso."));
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] string email, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(email)) 
                return BadRequest(new MessageResponseDTO("E-mail é obrigatório."));

            var result = await _authService.SolicitarRecuperacaoSenhaAsync(email, cancellationToken);
            
            if (result.IsFailure)
                return Ok(new MessageResponseDTO("Se o e-mail existir, um link de recuperação foi enviado."));

            return Ok(new { 
                Mensagem = "Token gerado com sucesso (Simulação de E-mail)", 
                TokenTemporario = result.Value 
            });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO resetDto, CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid) 
                return BadRequest(ModelState);

            var result = await _authService.RedefinirSenhaAsync(resetDto, cancellationToken);

            if (result.IsFailure)
                return BadRequest(new MessageResponseDTO("Token inválido ou expirado. Solicite uma nova recuperação."));

            return Ok(new MessageResponseDTO("Senha redefinida com sucesso. Todas as sessões antigas foram desconectadas."));
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
        {
            var refreshTokenAntigo = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshTokenAntigo))
                return Unauthorized(new MessageResponseDTO("Sessão expirada. Faça login novamente."));

            var result = await _authService.RenovarTokenAsync(refreshTokenAntigo, cancellationToken);

            if (result.IsFailure)
            {
                _logger.LogWarning("Tentativa de refresh token falhou: {Erro}", result.Error.Description);
                ClearTokenCookies();
                return Unauthorized(new MessageResponseDTO(result.Error.Description));
            }

            var (novoJwt, novoRefreshToken) = result.Value;
            SetTokenCookies(novoJwt, novoRefreshToken);

            return Ok(new MessageResponseDTO("Tokens renovados com sucesso!"));
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout(CancellationToken cancellationToken)
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
            {
                var result = await _authService.InvalidarRefreshTokenAsync(refreshToken, cancellationToken);
                if (result.IsFailure)
                {
                    _logger.LogWarning("Falha ao invalidar token no banco: {Erro}", result.Error.Description);
                }
            }

            ClearTokenCookies();
            return Ok(new MessageResponseDTO("Você saiu do sistema!"));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("promover/{email}")]
        public async Task<IActionResult> Promover(string email, CancellationToken cancellationToken)
        {
            var result = await _authService.PromoverParaAdminAsync(email, cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error == AuthErrors.UserNotFound)
                    return NotFound(new MessageResponseDTO(result.Error.Description));

                return BadRequest(new MessageResponseDTO(result.Error.Description));
            }

            return Ok(new MessageResponseDTO($"O usuário {email} foi promovido."));
        }

        [Authorize]
        [HttpGet("perfil")]
        public async Task<IActionResult> MeuPerfil(CancellationToken cancellationToken)
        {
            var emailUser = User.FindFirst(ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(emailUser))
                return Unauthorized();

            var result = await _authService.ObterPerfilAsync(emailUser, cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error == AuthErrors.UserNotFound)
                {
                    ClearTokenCookies();
                    return NotFound(new MessageResponseDTO(result.Error.Description));
                }
                return BadRequest(new MessageResponseDTO(result.Error.Description));
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