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
using ApiAutenticacao.Validations;
using ApiAutenticacao.Services;
using ApiAutenticacao.Repositories;

namespace ApiAutenticacao.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v1/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IValidator<RegisterDTO> _registerValidator;
        private readonly IValidator<LoginDTO> _loginValidator;
        private readonly IValidator<ConfirmEmailDTO> _confirmEmailValidator;
        private readonly IValidator<ResendConfirmationDTO> _resendConfirmationValidator;
        private readonly IValidator<ForgotPasswordDTO> _forgotPasswordValidator;
        private readonly IValidator<ChangePasswordDTO> _changePasswordValidator;
        private readonly IValidator<ResetPasswordDTO> _resetPasswordValidator;
        private readonly IValidator<PromoverDTO> _promoverValidator;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IValidator<RegisterDTO> registerValidator,
            IValidator<LoginDTO> loginValidator,
            IValidator<ConfirmEmailDTO> confirmEmailValidator,
            IValidator<ResendConfirmationDTO> resendConfirmationValidator,
            IValidator<ForgotPasswordDTO> forgotPasswordValidator,
            IValidator<ChangePasswordDTO> changePasswordValidator,
            IValidator<ResetPasswordDTO> resetPasswordValidator,
            IValidator<PromoverDTO> promoverValidator,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _registerValidator = registerValidator;
            _loginValidator = loginValidator;
            _confirmEmailValidator = confirmEmailValidator;
            _resendConfirmationValidator = resendConfirmationValidator;
            _forgotPasswordValidator = forgotPasswordValidator;
            _changePasswordValidator = changePasswordValidator;
            _resetPasswordValidator = resetPasswordValidator;
            _promoverValidator = promoverValidator;
            _logger = logger;
        }

        [HttpPost("register")]
        [Tags("1. Acesso e Registro")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto, CancellationToken cancellationToken)
        {
            var validationResult = await _registerValidator.ValidateAsync(registerDto, cancellationToken);
            if (!validationResult.IsValid)
            {
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));
            }

            var result = await _authService.RegistrarAsync(registerDto, cancellationToken);
            
            if (result.IsFailure)
                return HandleFailure(result);

            return Ok(new MessageResponseDTO("Usuário cadastrado com sucesso."));
        }

        [HttpPost("login")]
        [EnableRateLimiting("LoginRateLimit")]
        [Tags("1. Acesso e Registro")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto, CancellationToken cancellationToken)
        {
            var validationResult = await _loginValidator.ValidateAsync(loginDto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.LoginAsync(loginDto, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            var (jwt, refreshToken) = result.Value;
            SetTokenCookies(jwt, refreshToken);

            return Ok(new MessageResponseDTO("Login realizado com sucesso."));
        }

        [HttpPost("confirm-email")]
        [EnableRateLimiting("LoginRateLimit")]
        [Tags("2. Confirmação e Recuperação")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDTO confirmDto, CancellationToken cancellationToken)
        {
            var validationResult = await _confirmEmailValidator.ValidateAsync(confirmDto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.ConfirmarEmailAsync(confirmDto, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            return Ok(new MessageResponseDTO("E-mail confirmado com sucesso. Você já pode fazer login no sistema."));
        }

        [HttpPost("resend-confirmation")]
        [EnableRateLimiting("LoginRateLimit")]
        [Tags("2. Confirmação e Recuperação")]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationDTO request, CancellationToken cancellationToken)
        {
            var validationResult = await _resendConfirmationValidator.ValidateAsync(request, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.ReenviarCodigoConfirmacaoAsync(request, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            return Ok(new MessageResponseDTO("Um novo código foi gerado e enviado para o seu e-mail."));
        }

        [HttpPost("forgot-password")]
        [EnableRateLimiting("LoginRateLimit")]
        [Tags("2. Confirmação e Recuperação")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO dto, CancellationToken cancellationToken)
        {
            var validationResult = await _forgotPasswordValidator.ValidateAsync(dto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.SolicitarRecuperacaoSenhaAsync(dto.Email, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);
            
            return Ok(new MessageResponseDTO("Se o e-mail existir em nosso sistema, um link de recuperação será enviado."));
        }

        [HttpPost("reset-password")]
        [EnableRateLimiting("LoginRateLimit")]
        [Tags("2. Confirmação e Recuperação")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO resetDto, CancellationToken cancellationToken)
        {
            var validationResult = await _resetPasswordValidator.ValidateAsync(resetDto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.RedefinirSenhaAsync(resetDto, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            return Ok(new MessageResponseDTO("Senha redefinida com sucesso. Todas as sessões antigas foram desconectadas."));
        }

        [HttpPost("refresh")]
        [Tags("1. Acesso e Registro")]
        public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
        {
            var refreshTokenAntigo = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshTokenAntigo))
                return Unauthorized(new MessageResponseDTO("Sessão expirada. Faça login novamente."));

            var result = await _authService.RenovarTokenAsync(refreshTokenAntigo, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);
   
            var (novoJwt, novoRefreshToken) = result.Value;
            SetTokenCookies(novoJwt, novoRefreshToken);

            return Ok(new MessageResponseDTO("Tokens renovados com sucesso!"));
        }

        [HttpPost("logout")]
        [Tags("1. Acesso e Registro")]
        public async Task<IActionResult> Logout(CancellationToken cancellationToken)
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
            {
                var result = await _authService.InvalidarRefreshTokenAsync(refreshToken, cancellationToken);
              if (result.IsFailure)
                return HandleFailure(result);
            }

            ClearTokenCookies();
            return Ok(new MessageResponseDTO("Você saiu do sistema!"));
        }

        [Authorize]
        [HttpPost("logout-all")]
        [Tags("1. Acesso e Registro")]
        public async Task<IActionResult> LogoutAll(CancellationToken cancellationToken)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            
            if (string.IsNullOrEmpty(email))
                return Unauthorized();

            var result = await _authService.LogoutCascataAsync(email, cancellationToken);

                if (result.IsFailure)
                    return HandleFailure(result);

            ClearTokenCookies();
            return Ok(new MessageResponseDTO("Você foi desconectado de todos os dispositivos com sucesso!"));
        }

        [Authorize]
        [HttpPost("change-password")]
        [Tags("3. Gestão de Perfil")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDTO dto, CancellationToken cancellationToken)
        {
            var validationResult = await _changePasswordValidator.ValidateAsync(dto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            
            if (string.IsNullOrEmpty(email))
                return Unauthorized();

            var result = await _authService.AlterarSenhaAsync(email, dto, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            ClearTokenCookies();
            
            return Ok(new MessageResponseDTO("Senha alterada com sucesso. Por favor, faça login novamente com a nova senha."));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("promover/email")]
        [Tags("4. Administração")]
        public async Task<IActionResult> Promover([FromBody] PromoverDTO dto, CancellationToken cancellationToken)
        {
            var validationResult = await _promoverValidator.ValidateAsync(dto, cancellationToken);
            if (!validationResult.IsValid)
                return BadRequest(validationResult.Errors.Select(e => e.ErrorMessage));

            var result = await _authService.PromoverParaAdminAsync(dto.Email, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            return Ok(new MessageResponseDTO($"O usuário {dto.Email} foi promovido."));
        }

        [Authorize]
        [HttpDelete("delete-account")]
        [Tags("3. Gestão de Perfil")]
        public async Task<IActionResult> DeleteAccount(CancellationToken cancellationToken)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            
            if (string.IsNullOrEmpty(email))
                return Unauthorized();

            var result = await _authService.DeletarContaAsync(email, cancellationToken);

            if (result.IsFailure)
                return HandleFailure(result);

            ClearTokenCookies();
            
            return Ok(new MessageResponseDTO("Sua conta foi excluída com sucesso."));
        }

        [Authorize]
        [HttpGet("perfil")]
        [Tags("3. Gestão de Perfil")]
        public async Task<IActionResult> MeuPerfil(CancellationToken cancellationToken)
        {
            var emailUser = User.FindFirst(ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(emailUser))
                return Unauthorized();

            var result = await _authService.ObterPerfilAsync(emailUser, cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error == AuthErrors.UserNotFound)
                    ClearTokenCookies();
                
                return HandleFailure(result);
            }

            return Ok(result.Value);
        }

        private IActionResult HandleFailure(Result result)
        {
            var response = new MessageResponseDTO(result.Error.Description);

            return result.Error.Type switch
            {
                ErrorType.NotFound => NotFound(response),
                ErrorType.Conflict => Conflict(response),
                ErrorType.Unauthorized => Unauthorized(response),
                ErrorType.Forbidden => StatusCode(StatusCodes.Status403Forbidden, response),
                _ => BadRequest(response)
            };
        }

        private void SetTokenCookies(string jwt, string refreshToken)
        {
            var secure = HttpContext.Request.IsHttps ||
                !HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment();
            Response.Cookies.Append("jwt", jwt, new CookieOptions { HttpOnly = true, Secure = secure, SameSite = SameSiteMode.Strict, Path = "/", Expires = DateTime.UtcNow.AddMinutes(15) });
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions { HttpOnly = true, Secure = secure, SameSite = SameSiteMode.Strict, Path = "/", Expires = DateTime.UtcNow.AddDays(7) });
        }

        private void ClearTokenCookies()
        {
            Response.Cookies.Delete("jwt", new CookieOptions { Path = "/" });
            Response.Cookies.Delete("refreshToken", new CookieOptions { Path = "/" });
        }
    }
}