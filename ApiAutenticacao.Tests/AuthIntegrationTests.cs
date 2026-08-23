using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using ApiAutenticacao.Data;
using ApiAutenticacao.DTOs;
using Xunit;

namespace ApiAutenticacao.Tests
{
    public class AuthIntegrationTests : IClassFixture<CustomApiFactory>
    {
        private readonly HttpClient _client;
        private readonly CustomApiFactory _factory;

        public AuthIntegrationTests(CustomApiFactory factory)
        {
            _factory = factory;
            _client = factory.CreateClient();
        }

        [Fact]
        public async Task Register_DeveRetornar200_QuandoDadosValidos()
        {
            var emailUnico = $"teste_{Guid.NewGuid()}@gmail.com";
            var request = new { Email = emailUnico, Password = "SenhaSegura123!" };

            var response = await _client.PostAsJsonAsync("/api/v1/auth/register", request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task Register_DeveRetornar400_QuandoEmailDuplicado()
        {
            var emailUnico = $"duplicado_{Guid.NewGuid()}@gmail.com";
            var request = new { Email = emailUnico, Password = "SenhaSegura123!" };

            await _client.PostAsJsonAsync("/api/v1/auth/register", request);
            var response = await _client.PostAsJsonAsync("/api/v1/auth/register", request);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Login_DeveRetornar403_QuandoEmailNaoConfirmado()
        {
            var emailUnico = $"bloqueado_{Guid.NewGuid()}@gmail.com";
            var request = new { Email = emailUnico, Password = "SenhaSegura123!" };

            await _client.PostAsJsonAsync("/api/v1/auth/register", request);
            var response = await _client.PostAsJsonAsync("/api/v1/auth/login", request);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task FluxoCompleto_DevePermitirLogin_AposConfirmarEmail()
        {
            var emailUnico = $"fluxo_{Guid.NewGuid()}@gmail.com";
            var registroRequest = new { Email = emailUnico, Password = "SenhaSegura123!" };
            await _client.PostAsJsonAsync("/api/v1/auth/register", registroRequest);

            string codigoSecreto = string.Empty;
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var user = db.Users.First(u => u.Email == emailUnico);
                codigoSecreto = user.EmailConfirmationToken!;
            }

            var confirmRequest = new { Email = emailUnico, Code = codigoSecreto };
            var confirmResponse = await _client.PostAsJsonAsync("/api/v1/auth/confirm-email", confirmRequest);
            Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

            var loginRequest = new { Email = emailUnico, Password = "SenhaSegura123!" };
            var loginResponse = await _client.PostAsJsonAsync("/api/v1/auth/login", loginRequest);

            Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        }

        [Fact]
        public async Task ResendConfirmation_DeveRetornar200_QuandoUsuarioExiste()
        {
            var emailUnico = $"resend_{Guid.NewGuid()}@gmail.com";
            await _client.PostAsJsonAsync("/api/v1/auth/register", new { Email = emailUnico, Password = "xxxxxxxxxxxxxx" });

            var resendRequest = new ResendConfirmationDTO { Email = emailUnico };
            var response = await _client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", resendRequest);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
