using System.Text;
using System.Security.Cryptography;
using Models;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUnitOfWork _uow;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthService> _logger;
        private readonly SessionService _sessions;

        public AuthService(IUnitOfWork uow, IEmailService emailService, ILogger<AuthService> logger, SessionService sessions)
        {
            _uow = uow;
            _emailService = emailService;
            _logger = logger;
            _sessions = sessions;
        }

        public async Task<Result> RegistrarAsync(RegisterDTO registerDto, CancellationToken cancellationToken = default)
        {
            var email = NormalizeEmail(registerDto.Email);
            var existingUser = await _uow.Users.GetByEmailAsync(email, cancellationToken);
            if (existingUser != null)
            {
                return Result.Failure(AuthErrors.EmailAlreadyExists);
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(4);
            var tokenCode = (BitConverter.ToUInt32(tokenBytes, 0) % 900000 + 100000).ToString();

            var user = new User
            {
                Email = email,
                PasswordHash = await Task.Run(() => BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)),
                EmailConfirmed = false,
                EmailConfirmationToken = tokenCode,
                EmailConfirmationTokenExpires = DateTimeOffset.UtcNow.AddMinutes(10)
            };

            await _uow.Users.AddAsync(user, cancellationToken);
            await _uow.CommitAsync(cancellationToken);
            try
            {
                await _emailService.EnviarEmailAsync(
                    user.Email,
                    "Código de Confirmação",
                    $"Seu código de confirmação é: {tokenCode}. Ele expira em 10 minutos."
                );
                _logger.LogInformation("Email de confirmação enviado com sucesso para: {Email}", user.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha ao enviar email de confirmação para {Email}. Usuário registrado mas precisará reenviar o código.", user.Email);
            }

            return Result.Success();
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> LoginAsync(LoginDTO loginDto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(loginDto.Email), cancellationToken);

            if (user == null)
            {
                _logger.LogWarning("Tentativa de login com email não registrado: {Email}", loginDto.Email);
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
            {
                _logger.LogWarning("Tentativa de login com conta bloqueada: {Email}. Desbloqueio em: {LockoutEnd}", loginDto.Email, user.LockoutEnd);
                return Result<(string, string)>.Failure(AuthErrors.AccountLocked);
            }

            if (user.PasswordHash == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 5)
                {
                    user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
                    _logger.LogWarning("Conta bloqueada por múltiplas tentativas de login falhas: {Email}. Tentativas: {Count}", loginDto.Email, user.AccessFailedCount);
                }
                else
                {
                    _logger.LogWarning("Falha na tentativa de login: {Email}. Tentativas falhadas: {Count}/5", loginDto.Email, user.AccessFailedCount);
                }
                await _uow.CommitAsync(cancellationToken);
                return Result<(string, string)>.Failure(AuthErrors.InvalidCredentials);
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Tentativa de login com email não confirmado: {Email}", loginDto.Email);
                return Result<(string, string)>.Failure(new Error("EmailNotConfirmed", "Por favor, confirme seu e-mail antes de fazer login.", ErrorType.Forbidden));
            }

            user.AccessFailedCount = 0;
            user.LockoutEnd = null;

            var credentials = _sessions.Create(user);
            await _uow.CommitAsync(cancellationToken);

            _logger.LogInformation("Login bem-sucedido para: {Email}", loginDto.Email);

            return Result<(string, string)>.Success(credentials);
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo, CancellationToken cancellationToken = default)
        {
            return await _sessions.RefreshAsync(refreshTokenAntigo, cancellationToken);
        }

        public async Task<Result> InvalidarRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            await _sessions.RevokeAsync(refreshToken, null, null, cancellationToken);
            return Result.Success();
        }

        public async Task<Result> PromoverParaAdminAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
            if (user == null)
            {
                _logger.LogWarning("Tentativa de promover usuário não encontrado: {Email}", email);
                return Result.Failure(AuthErrors.UserNotFound);
            }

            user.Role = "Admin";
            user.SecurityStamp = Guid.NewGuid().ToString();
            await _sessions.RevokeAllAsync(user.Id, cancellationToken);
            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogCritical("AUDITORIA: Usuário promovido a Admin: {Email}", email);
            return Result.Success();
        }

        public async Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
            if (user == null)
                return Result<UserProfileResponseDTO?>.Failure(AuthErrors.UserNotFound);

            var profile = new UserProfileResponseDTO
            {
                Id = user.Id,
                Email = user.Email,
                Role = user.Role,
                HasPassword = user.PasswordHash != null,
            };

            return Result<UserProfileResponseDTO?>.Success(profile);
        }

        public async Task<Result> DeletarContaAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
            
            if (user == null)
                return Result.Failure(AuthErrors.UserNotFound);

            user.DeletedAt = DateTimeOffset.UtcNow;
            user.SecurityStamp = Guid.NewGuid().ToString();
            await _sessions.RevokeAllAsync(user.Id, cancellationToken);

            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogInformation("Conta deletada pelo usuário: {Email}", email);
            return Result.Success();
        }

        public async Task<Result<string>> SolicitarRecuperacaoSenhaAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
            if (user == null)
            {
                _logger.LogInformation("Recuperação de senha solicitada para email não registrado: {Email}", email);
                return Result<string>.Failure(AuthErrors.UserNotFound);
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var token = Convert.ToBase64String(tokenBytes);

            user.PasswordResetToken = ComputeSha256Hash(token);
            user.ResetTokenExpires = DateTimeOffset.UtcNow.AddHours(1);

            await _uow.CommitAsync(cancellationToken);

            try
            {
                await _emailService.EnviarEmailAsync(
                    user.Email,
                    "Recuperação de senha",
                    $"Use este token para redefinir sua senha: {token}. Ele expira em 1 hora.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha ao enviar recuperação de senha para {Email}.", user.Email);
            }

            _logger.LogInformation("Token de recuperação de senha gerado para: {Email}", user.Email);
            return Result<string>.Success(token);
        }

        public async Task<Result> RedefinirSenhaAsync(ResetPasswordDTO resetDto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(resetDto.Email), cancellationToken);
             
            if (user == null || 
                user.PasswordResetToken == null ||
                user.PasswordResetToken != ComputeSha256Hash(resetDto.Token) ||
                !user.ResetTokenExpires.HasValue ||
                user.ResetTokenExpires <= DateTimeOffset.UtcNow)
            {
                _logger.LogWarning("Tentativa de redefinir senha com token inválido ou expirado: {Email}", resetDto.Email);
                return Result.Failure(AuthErrors.InvalidToken);
            }

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(resetDto.NovaSenha, workFactor: 11);
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;
            user.SecurityStamp = Guid.NewGuid().ToString();
            await _sessions.RevokeAllAsync(user.Id, cancellationToken);
            user.AccessFailedCount = 0;
            user.LockoutEnd = null;

            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogInformation("Senha redefinida com sucesso para: {Email}", resetDto.Email);
            return Result.Success();
        }

        public async Task<Result> AlterarSenhaAsync(string email, ChangePasswordDTO dto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
        
            if (user == null)
            return Result.Failure(AuthErrors.UserNotFound);

            if (user.PasswordHash == null || !BCrypt.Net.BCrypt.Verify(dto.SenhaAtual, user.PasswordHash))
            return Result.Failure(new Error("InvalidCurrentPassword", "A senha atual está incorreta."));

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NovaSenha, workFactor: 11);
            user.SecurityStamp = Guid.NewGuid().ToString();
            await _sessions.RevokeAllAsync(user.Id, cancellationToken);

            await _uow.CommitAsync(cancellationToken);
        
            _logger.LogInformation("Senha alterada internamente pelo usuário: {Email}", email);
            return Result.Success();
        }

        public async Task<Result> ConfirmarEmailAsync(ConfirmEmailDTO dto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(dto.Email), cancellationToken);

            if (user == null || user.EmailConfirmationToken != dto.Code)
            {
                return Result.Failure(AuthErrors.InvalidCredentials);
            }

            if (user.EmailConfirmed)
            {
                return Result.Failure(new Error("EmailAlreadyConfirmed", "E-mail já confirmado."));
            }

            if (!user.EmailConfirmationTokenExpires.HasValue || user.EmailConfirmationTokenExpires <= DateTimeOffset.UtcNow)
            {
                return Result.Failure(new Error("TokenExpired", "Código expirado."));
            }

            user.EmailConfirmed = true;
            user.EmailConfirmationToken = null;
            user.EmailConfirmationTokenExpires = null;

            await _uow.CommitAsync(cancellationToken);

            _logger.LogInformation("Email confirmado com sucesso para usuário: {Email}", user.Email);

            return Result.Success();
        }

        public async Task<Result> ReenviarCodigoConfirmacaoAsync(ResendConfirmationDTO dto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(dto.Email), cancellationToken);

            if (user == null)
                return Result.Failure(AuthErrors.UserNotFound);

            if (user.EmailConfirmed)
                return Result.Failure(new Error("EmailAlreadyConfirmed", "Este e-mail já está confirmado. Faça login no sistema."));

            var tokenBytes = RandomNumberGenerator.GetBytes(4);
            var novoCodigo = (BitConverter.ToUInt32(tokenBytes, 0) % 900000 + 100000).ToString();

            user.EmailConfirmationToken = novoCodigo;
            user.EmailConfirmationTokenExpires = DateTimeOffset.UtcNow.AddMinutes(10);

            await _uow.CommitAsync(cancellationToken);

            try
            {
                await _emailService.EnviarEmailAsync(
                    user.Email,
                    "Seu Novo Código de Confirmação",
                    $"Seu novo código é: {novoCodigo}. Ele expira em 10 minutos."
                );
                _logger.LogInformation("Código de confirmação reenviado para: {Email}", user.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha ao reenviar código de confirmação para {Email}. Código gerado mas não foi enviado.", user.Email);
            }

            return Result.Success();
        }

        public async Task<Result> LogoutCascataAsync(string email, CancellationToken cancellationToken = default)
{
    var user = await _uow.Users.GetByEmailAsync(NormalizeEmail(email), cancellationToken);
    
    if (user == null)
        return Result.Failure(AuthErrors.UserNotFound);

    await _sessions.RevokeAllAsync(user.Id, cancellationToken);
    user.SecurityStamp = Guid.NewGuid().ToString();

    await _uow.CommitAsync(cancellationToken);
    _logger.LogInformation("Logout em cascata (LogoutAll) realizado: {Email}", email);

    return Result.Success();
}

        private static string ComputeSha256Hash(string rawData)
        {
            using var sha256Hash = SHA256.Create();
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return Convert.ToBase64String(bytes);
        }

        private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();
    }
}
