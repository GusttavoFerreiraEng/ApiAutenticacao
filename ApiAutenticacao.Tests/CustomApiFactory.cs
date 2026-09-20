using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using ApiAutenticacao.Data;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Services;
using System.Linq;

namespace ApiAutenticacao.Tests
{
    public class CustomApiFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                var descriptorsToRemove = services
                    .Where(d => d.ServiceType == typeof(DbContextOptions<AppDbContext>)
                             || d.ServiceType == typeof(DbContextOptions)
                             || d.ServiceType == typeof(AppDbContext)
                             || d.ServiceType == typeof(DbContext)
                             || d.ServiceType.FullName?.Contains("DbContextOptions") == true)
                    .ToList();

                foreach (var descriptor in descriptorsToRemove)
                {
                    services.Remove(descriptor);
                }

                services.AddDbContext<AppDbContext>(options =>
                {
                    options.UseInMemoryDatabase("BancoDeTestesAuth");
                });

                var emailDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IEmailService));
                if (emailDescriptor != null) services.Remove(emailDescriptor);

                var tokenCleanupDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                    && d.ImplementationType == typeof(TokenCleanupService));
                if (tokenCleanupDescriptor != null) services.Remove(tokenCleanupDescriptor);

                var mockEmailService = new Mock<IEmailService>();
                services.AddSingleton(mockEmailService.Object);
            });
        }
    }
}
