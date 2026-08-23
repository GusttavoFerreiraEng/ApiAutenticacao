using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Models;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Common;
using ApiAutenticacao.common;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUnitOfWork _uow;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthService> _logger;
        private readonly string _jwtKey;

        public AuthService(IUnitOfWork uow, IConfiguration configuration, IEmailService emailService, ILogger<AuthService> logger)
        {
            _uow = uow;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
            _jwtKey = _configuration["jwt:Key"] ?? throw new InvalidOperationException("Chave JWT não configurada.");
        }

        public async Task<Result> RegistrarAsync(RegisterDTO registerDto, CancellationToken cancellationToken = default)
        {
            var existingUser = await _uow.Users.GetByEmailAsync(registerDto.Email, cancellationToken);
            if (existingUser != null)
            {
                return Result.Failure(AuthErrors.EmailAlreadyExists);
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(4);
            var tokenCode = (BitConverter.ToUInt32(tokenBytes, 0) % 900000 + 100000).ToString();

            var user = new User
            {
                Email = registerDto.Email,
                PasswordHash = await Task.Run(() => BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 11)),
                EmailConfirmed = false,
                EmailConfirmationToken = tokenCode,
                EmailConfirmationTokenExpires = DateTimeOffset.UtcNow.AddSeconds(60)
            };

            await _uow.Users.AddAsync(user, cancellationToken);
            await _uow.CommitAsync(cancellationToken);
            try
            {
                await _emailService.EnviarEmailAsync(
                    user.Email,
                    "Código de Confirmação",
                    $"Seu código de confirmação é: {tokenCode}. Ele expira em 60 segundos."
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
            var user = await _uow.Users.GetByEmailAsync(loginDto.Email, cancellationToken);

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

            if (!BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
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
                return Result<(string, string)>.Failure(new Error("EmailNotConfirmed", "Por favor, confirme seu e-mail antes de fazer login."));
            }

            user.AccessFailedCount = 0;
            user.LockoutEnd = null;

            var jwt = GerarJwt(user);
            var refreshTokenRaw = GerarRefreshToken();

            var novoToken = new RefreshToken
            {
                TokenHash = ComputeSha256Hash(refreshTokenRaw),
                ExpiryTime = DateTimeOffset.UtcNow.AddDays(7)
            };
            
            user.RefreshTokens.Add(novoToken);
            await _uow.CommitAsync(cancellationToken);

            _logger.LogInformation("Login bem-sucedido para: {Email}", loginDto.Email);

            return Result<(string, string)>.Success((jwt, refreshTokenRaw));
        }

        public async Task<Result<(string AccessToken, string RefreshToken)>> RenovarTokenAsync(string refreshTokenAntigo, CancellationToken cancellationToken = default)
        {
            var providedHash = ComputeSha256Hash(refreshTokenAntigo);
            
            var user = await _uow.Users.GetByRefreshTokenHashAsync(providedHash, cancellationToken);

            if (user == null)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
            }

            // Pega o token específico dentro da lista do usuário
            var tokenAtual = user.RefreshTokens.FirstOrDefault(rt => 
                rt.TokenHash == providedHash || rt.PreviousTokenHash == providedHash);

            if (tokenAtual == null || tokenAtual.ExpiryTime <= DateTimeOffset.UtcNow)
            {
                return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
            }

            var novoJwt = GerarJwt(user);
            var novoRefreshTokenRaw = GerarRefreshToken();

            tokenAtual.PreviousTokenHash = tokenAtual.TokenHash;
            tokenAtual.PreviousTokenGraceExpiry = DateTimeOffset.UtcNow.AddMinutes(1);
            
            tokenAtual.TokenHash = ComputeSha256Hash(novoRefreshTokenRaw);
            tokenAtual.ExpiryTime = DateTimeOffset.UtcNow.AddDays(7);

            await _uow.CommitAsync(cancellationToken);

            return Result<(string, string)>.Success((novoJwt, novoRefreshTokenRaw));
        }

        public async Task<Result> InvalidarRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var hash = ComputeSha256Hash(refreshToken);
            var user = await _uow.Users.GetByRefreshTokenHashAsync(hash, cancellationToken);

            if (user != null)
            {
                var tokenParaRemover = user.RefreshTokens.FirstOrDefault(rt => rt.TokenHash == hash);
                if (tokenParaRemover != null)
                {
                    user.RefreshTokens.Remove(tokenParaRemover);
                    await _uow.CommitAsync(cancellationToken);
                    _logger.LogInformation("Refresh token invalidado para usuário: {Email}", user.Email);
                }
            }

            return Result.Success();
        }

        public async Task<Result> PromoverParaAdminAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(email, cancellationToken);
            if (user == null)
            {
                _logger.LogWarning("Tentativa de promover usuário não encontrado: {Email}", email);
                return Result.Failure(AuthErrors.UserNotFound);
            }

            user.Role = "Admin";
            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogCritical("AUDITORIA: Usuário promovido a Admin: {Email}", email);
            return Result.Success();
        }

        public async Task<Result<UserProfileResponseDTO?>> ObterPerfilAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(email, cancellationToken);
            if (user == null)
                return Result<UserProfileResponseDTO?>.Failure(AuthErrors.UserNotFound);

            var profile = new UserProfileResponseDTO
            {
                Id = user.Id,
                Email = user.Email,
                Role = user.Role,
                SecurityStamp = user.SecurityStamp
            };

            return Result<UserProfileResponseDTO?>.Success(profile);
        }

        public async Task<Result<string>> SolicitarRecuperacaoSenhaAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(email, cancellationToken);
            if (user == null)
            {
                _logger.LogInformation("Recuperação de senha solicitada para email não registrado: {Email}", email);
                return Result<string>.Failure(AuthErrors.UserNotFound);
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var token = Convert.ToBase64String(tokenBytes);

            user.PasswordResetToken = token;
            user.ResetTokenExpires = DateTimeOffset.UtcNow.AddMinutes(15);

            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogInformation("Token de recuperação de senha gerado para: {Email}", email);
            return Result<string>.Success(token);
        }

        public async Task<Result> RedefinirSenhaAsync(ResetPasswordDTO resetDto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(resetDto.Email, cancellationToken);
             
            if (user == null || 
                user.PasswordResetToken != resetDto.Token || 
                user.ResetTokenExpires < DateTimeOffset.UtcNow)
            {
                _logger.LogWarning("Tentativa de redefinir senha com token inválido ou expirado: {Email}", resetDto.Email);
                return Result.Failure(AuthErrors.InvalidToken);
            }

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(resetDto.NovaSenha, workFactor: 11);
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;
            user.SecurityStamp = Guid.NewGuid().ToString();
            user.AccessFailedCount = 0;
            user.LockoutEnd = null;

            await _uow.CommitAsync(cancellationToken);
            
            _logger.LogInformation("Senha redefinida com sucesso para: {Email}", resetDto.Email);
            return Result.Success();
        }

        public async Task<Result> ConfirmarEmailAsync(ConfirmEmailDTO dto, CancellationToken cancellationToken = default)
        {
            var user = await _uow.Users.GetByEmailAsync(dto.Email, cancellationToken);

            if (user == null || user.EmailConfirmationToken != dto.Code)
            {
                return Result.Failure(AuthErrors.InvalidCredentials);
            }

            if (user.EmailConfirmed)
            {
                return Result.Failure(new Error("EmailAlreadyConfirmed", "E-mail já confirmado."));
            }

            if (user.EmailConfirmationTokenExpires < DateTimeOffset.UtcNow)
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
            var user = await _uow.Users.GetByEmailAsync(dto.Email, cancellationToken);

            if (user == null)
                return Result.Failure(AuthErrors.UserNotFound);

            if (user.EmailConfirmed)
                return Result.Failure(new Error("EmailAlreadyConfirmed", "Este e-mail já está confirmado. Faça login no sistema."));

            var tokenBytes = RandomNumberGenerator.GetBytes(4);
            var novoCodigo = (BitConverter.ToUInt32(tokenBytes, 0) % 900000 + 100000).ToString();

            user.EmailConfirmationToken = novoCodigo;
            user.EmailConfirmationTokenExpires = DateTimeOffset.UtcNow.AddSeconds(60);

            await _uow.CommitAsync(cancellationToken);

            try
            {
                await _emailService.EnviarEmailAsync(
                    user.Email,
                    "Seu Novo Código de Confirmação",
                    $"Seu novo código é: {novoCodigo}. Ele expira em 60 segundos."
                );
                _logger.LogInformation("Código de confirmação reenviado para: {Email}", user.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha ao reenviar código de confirmação para {Email}. Código gerado mas não foi enviado.", user.Email);
            }

            return Result.Success();
        }

        private string GerarJwt(User user)
        {
            var chaveBytes = Encoding.UTF8.GetBytes(_jwtKey);
            var credenciais = new SigningCredentials(new SymmetricSecurityKey(chaveBytes), SecurityAlgorithms.HmacSha256);

            var informacoes = new[]
            {
              new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
              new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
              new Claim(ClaimTypes.Email, user.Email),
              new Claim(ClaimTypes.Role, user.Role),
              new Claim("SecurityStamp", user.SecurityStamp)
            };

            var tokenObjeto = new JwtSecurityToken(
                issuer: _configuration["jwt:Issuer"],
                audience: _configuration["jwt:Audience"],
                claims: informacoes,
                expires: DateTime.UtcNow.AddMinutes(15), 
                signingCredentials: credenciais
                
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenObjeto);
        }

        private string GerarRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private static string ComputeSha256Hash(string rawData)
        {
            using var sha256Hash = SHA256.Create();
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return Convert.ToBase64String(bytes);
        }
    }
}