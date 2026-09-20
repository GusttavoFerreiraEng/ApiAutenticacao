using System;
using System.Threading;
using System.Threading.Tasks;
using ApiAutenticacao.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;

namespace ApiAutenticacao.Services
{
    public class TokenCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<TokenCleanupService> _logger;
        private const int CleanupIntervalHours = 24;

        public TokenCleanupService(IServiceProvider serviceProvider, ILogger<TokenCleanupService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("TokenCleanupService iniciado. Próxima limpeza em {Hours} horas.", CleanupIntervalHours);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromHours(CleanupIntervalHours), stoppingToken);
                    
                    _logger.LogInformation("Iniciando limpeza de Refresh Tokens expirados...");

                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                        var deletedCount = await dbContext.RefreshTokens
                            .Where(rt => rt.ExpiryTime < DateTimeOffset.UtcNow)
                            .ExecuteDeleteAsync(stoppingToken);

                        _logger.LogInformation("Limpeza concluída. {Count} Refresh Tokens expirados removidos.", deletedCount);
                    }
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("TokenCleanupService foi cancelado.");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro ao limpar Refresh Tokens expirados. Próxima tentativa em {Hours} horas.", CleanupIntervalHours);
                }
            }
        }
    }
}

