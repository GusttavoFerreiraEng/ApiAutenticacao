using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using ApiAutenticacao.Authentication;
using ApiAutenticacao.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiAutenticacao.Tests;

public sealed class LocalCookieApiFactory : GoogleApiFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseEnvironment("Development");
    }
}

public sealed class PendingClockApiFactory : GoogleApiFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services => services.PostConfigure<CookieAuthenticationOptions>(
            GoogleAuthentication.PendingScheme, options => options.TimeProvider = Clock));
    }
}

// Cada caso usa um host próprio e o MySQL auth_test descartável exigido pela factory.
// Credenciais, cookies e hashes são usados somente em memória, sem gravação em fixtures.
public sealed class AccessCompatibilityTests
{
    private sealed record LocalUser(long Id, string Email, string Password, string Hash);
    private static HttpClient Client(GoogleApiFactory factory) => factory.CreateClient(new() { HandleCookies = false, AllowAutoRedirect = false });
    private static string Secret() => Guid.NewGuid().ToString("N") + "!";
    private static string Token(HttpResponseMessage response, string name) =>
        GoogleTestFlow.Cookies(response).Split("; ").Single(c => c.StartsWith(name + "=", StringComparison.Ordinal))[(name.Length + 1)..];
    private static void NoSession(HttpResponseMessage response) =>
        Assert.False(GoogleTestFlow.Cookies(response).Split("; ").Any(c => c.StartsWith("jwt=", StringComparison.Ordinal)), "A recusa não deve emitir uma sessão.");
    private static Task<HttpResponseMessage> Login(HttpClient client, string email, string password) =>
        client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
    private static Task<HttpResponseMessage> Link(HttpClient client, string pending, string password)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/google/link") { Content = JsonContent.Create(new { password }) };
        request.Headers.Add("Cookie", pending);
        return client.SendAsync(request);
    }
    private static Task<HttpResponseMessage> Validate(HttpClient client, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/internal/auth/validate");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(request);
    }
    private static async Task<LocalUser> Register(GoogleApiFactory factory, HttpClient client)
    {
        var email = $"Release.{Guid.NewGuid():N}@Example.Test";
        var password = Secret();
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password })).StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.AsNoTracking().SingleAsync(u => u.Email == email.ToLowerInvariant());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/confirm-email", new { email, code = user.EmailConfirmationToken })).StatusCode);
        return new(user.Id, user.Email, password, user.PasswordHash!);
    }

    [Fact]
    public async Task RegisteredLocalAccountAcceptsCaseAndTrimWithoutDuplicatingIdentity()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var login = await Login(client, "  " + user.Email.ToUpperInvariant() + "  ", user.Password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.True(new JwtSecurityTokenHandler().ReadJwtToken(Token(login, "jwt")).Subject == user.Id.ToString());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new { email = user.Email.ToUpperInvariant(), password = Secret() })).StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.CountAsync(u => u.Email == user.Email));
    }

    [Fact]
    public async Task WrongLocalPasswordUnknownEmailAndGoogleOnlyIdentityAreRefusedGenerically()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var local = await Register(factory, client);
        var email = $"passwordless.{Guid.NewGuid():N}@example.test";
        var google = await GoogleTestFlow.SignIn(factory, client, Guid.NewGuid().ToString("N"), email);
        Assert.Equal(HttpStatusCode.Redirect, google.StatusCode);
        using (var scope = factory.Services.CreateScope())
            Assert.Null((await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.SingleAsync(u => u.Email == email)).PasswordHash);
        var wrong = await Login(client, local.Email, Secret());
        var passwordless = await Login(client, email, Secret());
        var unknown = await Login(client, $"unknown.{Guid.NewGuid():N}@example.test", Secret());
        foreach (var response in new[] { wrong, passwordless, unknown })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            NoSession(response);
        }
        var generic = await wrong.Content.ReadAsStringAsync();
        Assert.True(generic == await passwordless.Content.ReadAsStringAsync(), "A conta sem senha usa a mesma mensagem genérica.");
        Assert.True(generic == await unknown.Content.ReadAsStringAsync(), "A conta inexistente usa a mesma mensagem genérica.");
    }

    [Fact]
    public async Task LinkingKeepsPasswordHashAndInternalIdAndBothLoginMethodsWork()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var before = await Login(client, user.Email, user.Password);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        var oldToken = Token(before, "jwt");
        var subject = Guid.NewGuid().ToString("N");
        var callback = await GoogleTestFlow.SignIn(factory, client, subject, " " + user.Email.ToUpperInvariant() + " ");
        Assert.True(callback.Headers.Location?.AbsolutePath == "/vincular-google");
        NoSession(callback);
        var pending = GoogleTestFlow.Cookies(callback);
        var wrong = await Link(client, pending, Secret());
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        NoSession(wrong);
        using (var scope = factory.Services.CreateScope())
            Assert.False(await scope.ServiceProvider.GetRequiredService<AppDbContext>().ExternalLogins.AnyAsync(l => l.Subject == subject));
        var linked = await Link(client, pending, user.Password);
        Assert.Equal(HttpStatusCode.OK, linked.StatusCode);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.Users.SingleAsync(u => u.Id == user.Id);
            Assert.True(stored.PasswordHash == user.Hash, "Vinculação não deve substituir o hash da senha.");
            Assert.Equal(user.Id, (await db.ExternalLogins.SingleAsync(l => l.Subject == subject)).UserId);
            Assert.Equal(1, await db.Users.CountAsync(u => u.Email == user.Email));
        }
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(client, oldToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Login(client, user.Email, user.Password)).StatusCode);
        var again = await GoogleTestFlow.SignIn(factory, client, subject, user.Email);
        Assert.True(again.Headers.Location?.AbsolutePath == "/dashboard");
        Assert.True(new JwtSecurityTokenHandler().ReadJwtToken(Token(again, "jwt")).Subject == user.Id.ToString());
    }

    [Fact]
    public async Task LinkWithoutPendingTicketReturnsUnauthorized()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var response = await client.PostAsJsonAsync("/api/v1/auth/google/link", new { password = Secret() });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        NoSession(response);
    }

    [Fact]
    public async Task ExpiredPendingTicketDoesNotCreateExternalLogin()
    {
        await using var factory = new PendingClockApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var subject = Guid.NewGuid().ToString("N");
        var callback = await GoogleTestFlow.SignIn(factory, client, subject, user.Email);
        factory.Clock.Advance(TimeSpan.FromMinutes(6));
        var expired = await Link(client, GoogleTestFlow.Cookies(callback), user.Password);
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        NoSession(expired);
        using var scope = factory.Services.CreateScope();
        Assert.False(await scope.ServiceProvider.GetRequiredService<AppDbContext>().ExternalLogins.AnyAsync(l => l.Subject == subject));
    }

    [Fact]
    public async Task ReusedPendingTicketDoesNotDuplicateOrRevokeSuccessfulSession()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var subject = Guid.NewGuid().ToString("N");
        var callback = await GoogleTestFlow.SignIn(factory, client, subject, user.Email);
        var pending = GoogleTestFlow.Cookies(callback);
        var first = await Link(client, pending, user.Password);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var reused = await Link(client, pending, user.Password);
        Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);
        NoSession(reused);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, Token(first, "jwt"))).StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<AppDbContext>().ExternalLogins.CountAsync(l => l.Subject == subject));
    }

    [Fact]
    public async Task RepeatedWrongLinkPasswordsLockAccountAndLimitRequests()
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var subject = Guid.NewGuid().ToString("N");
        var callback = await GoogleTestFlow.SignIn(factory, client, subject, user.Email);
        var pending = GoogleTestFlow.Cookies(callback);
        for (var attempt = 0; attempt < 5; attempt++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await Link(client, pending, Secret())).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await Link(client, pending, user.Password)).StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.Users.SingleAsync(u => u.Id == user.Id);
        Assert.Equal(5, stored.AccessFailedCount);
        Assert.True(stored.LockoutEnd > DateTimeOffset.UtcNow);
        Assert.True(stored.PasswordHash == user.Hash);
        Assert.False(await db.ExternalLogins.AnyAsync(l => l.Subject == subject));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("adulterated")]
    public async Task MissingOrAlteredStateDoesNotRedeemCodeOrIssueSession(string? state)
    {
        await using var factory = new GoogleApiFactory();
        using var client = Client(factory);
        var before = factory.Backchannel.Calls;
        var response = await client.GetAsync(GoogleAuthentication.Callback + "?code=invalid" + (state == null ? "" : "&state=" + state));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        NoSession(response);
        Assert.Equal(before, factory.Backchannel.Calls);
    }

    [Fact]
    public async Task SessionCookiesHaveLocalFlagsAndLogoutRevokesCopiedJwt()
    {
        await using var factory = new LocalCookieApiFactory();
        using var client = Client(factory);
        var user = await Register(factory, client);
        var login = await Login(client, user.Email, user.Password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var headers = login.Headers.GetValues("Set-Cookie").ToArray();
        foreach (var header in headers.Where(h => h.StartsWith("jwt=") || h.StartsWith("refreshToken=")))
        {
            var flags = header.Split(';').Skip(1).Select(x => x.Trim()).ToArray();
            Assert.Contains(flags, x => x.Equals("httponly", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(flags, x => x.Equals("samesite=strict", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(flags, x => x.StartsWith("domain=", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(flags, x => x.Equals("secure", StringComparison.OrdinalIgnoreCase));
        }
        var token = Token(login, "jwt");
        var logout = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        logout.Headers.Add("Cookie", GoogleTestFlow.Cookies(login));
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(logout)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(client, token)).StatusCode);
    }
}
