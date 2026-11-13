using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;

namespace ApiAutenticacao.Tests;

public sealed class SessionClock : TimeProvider
{
    private long offset;
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow.AddTicks(Interlocked.Read(ref offset));
    public void Advance(TimeSpan time) => Interlocked.Add(ref offset, time.Ticks);
    public void Reset() => Interlocked.Exchange(ref offset, 0);
}

public class SessionApiFactory : WebApplicationFactory<Program>
{
    public SessionClock Clock { get; } = new();
    public const string SigningKey = "test-only-session-key-2026-at-least-sixty-four-bytes-no-production-use";
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var connection = Environment.GetEnvironmentVariable("TEST_MYSQL_CONNECTION")
            ?? throw new InvalidOperationException("Execute os testes de sessão pelo compose.test.yaml com MySQL descartável.");
        if (!connection.Contains("Database=auth_test;", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Os testes exigem o banco descartável auth_test.");
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = connection,
            ["jwt:Key"] = SigningKey, ["jwt:Issuer"] = "session-tests", ["jwt:Audience"] = "session-tests",
            ["RateLimits:LoginPerMinute"] = "1000", ["RateLimits:GlobalPerMinute"] = "1000",
            ["Authentication:Google:ClientId"] = "", ["Authentication:Google:ClientSecret"] = "",
            ["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"] = "Warning",
            ["Logging:LogLevel:Microsoft.AspNetCore"] = "Warning"
        }));
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.RemoveAll<IEmailService>();
            services.AddSingleton(new Mock<IEmailService>().Object);
            var cleanup = services.SingleOrDefault(s => s.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService) && s.ImplementationType == typeof(TokenCleanupService));
            if (cleanup != null) services.Remove(cleanup);
        });
    }
}
