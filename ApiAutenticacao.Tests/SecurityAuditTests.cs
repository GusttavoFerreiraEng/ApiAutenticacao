using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiAutenticacao.Authentication;
using ApiAutenticacao.Data;
using ApiAutenticacao.Interfaces;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Models;

namespace ApiAutenticacao.Tests;

// Real MySQL auth_test and the application's HTTP pipeline. Only outbound e-mail
// and the Google backchannel are replaced, so no messages reach third parties.
// Secrets stay in memory; assertions never include credential or token values.
public sealed class SecurityAuditEmail : IEmailService
{
    private readonly ConcurrentDictionary<string, string> messages = new();
    public Task EnviarEmailAsync(string paraEmail, string assunto, string corpo)
    {
        messages[paraEmail] = corpo;
        return Task.CompletedTask;
    }
    public string RecoveryToken(string email)
    {
        if (!messages.TryGetValue(email, out var body))
            throw new InvalidOperationException("The disposable recovery message was not captured.");
        const string prefix = "Use este token para redefinir sua senha: ";
        if (!body.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("The disposable recovery message has an unexpected format.");
        return body[prefix.Length..].Split(". Ele expira", 2, StringSplitOptions.None)[0];
    }
}

public sealed class SecurityAuditApiFactory : GoogleApiFactory
{
    public SecurityAuditEmail Email { get; } = new();
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService>(Email);
        });
    }
}

public sealed class SecurityAuditTests
{
    private sealed record DisposableUser(long Id, string Email, string Password);
    private static string Secret() => Guid.NewGuid().ToString("N") + "!";
    private static HttpClient Client(SecurityAuditApiFactory factory) => factory.CreateClient(new()
        { HandleCookies = false, AllowAutoRedirect = false });
    private static string Access(HttpResponseMessage response) => GoogleTestFlow.Cookies(response)
        .Split("; ").Single(value => value.StartsWith("jwt=", StringComparison.Ordinal))[4..];
    private static async Task<DisposableUser> NewUser(SecurityAuditApiFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var password = Secret();
        var user = new User { Email = $"security.{Guid.NewGuid():N}@example.test",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password, 4), EmailConfirmed = true };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return new(user.Id, user.Email, password);
    }
    private static async Task<string> Login(HttpClient client, DisposableUser user)
    {
        using var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { user.Email, user.Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Access(response);
    }
    private static async Task<string> Recovery(SecurityAuditApiFactory factory, HttpClient client, DisposableUser user)
    {
        using var response = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { user.Email });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return factory.Email.RecoveryToken(user.Email);
    }
    private static Task<HttpResponseMessage> Reset(HttpClient client, DisposableUser user, string token, string password) =>
        client.PostAsJsonAsync("/api/v1/auth/reset-password", new { user.Email, token, novaSenha = password });
    private static Task<HttpResponseMessage> Validate(HttpClient client, string access)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/internal/auth/validate");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return client.SendAsync(request);
    }
    private static void NoSession(HttpResponseMessage response) => Assert.False(
        GoogleTestFlow.Cookies(response).Split("; ").Any(value => value.StartsWith("jwt=", StringComparison.Ordinal)),
        "A rejected authentication attempt must not issue a session.");

    [Fact]
    public async Task RecoveryIssuedBeforePasswordChangeCannotChangePasswordAgain()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var user = await NewUser(factory);
        var access = await Login(client, user);
        var recovery = await Recovery(factory, client, user);
        var changedPassword = Secret();
        var change = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/change-password")
            { Content = JsonContent.Create(new { senhaAtual = user.Password, novaSenha = changedPassword }) };
        change.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(change)).StatusCode);
        var replay = await Reset(client, user, recovery, Secret());
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        NoSession(replay);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/login",
            new { user.Email, password = changedPassword })).StatusCode);
    }

    [Fact]
    public async Task RecoveryIssuedBeforeGoogleLinkCannotChangePasswordAfterLink()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var user = await NewUser(factory);
        var recovery = await Recovery(factory, client, user);
        var subject = Guid.NewGuid().ToString("N");
        var pending = await GoogleTestFlow.SignIn(factory, client, subject, user.Email);
        Assert.True(pending.Headers.Location?.AbsolutePath == "/vincular-google");
        var link = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/google/link")
            { Content = JsonContent.Create(new { password = user.Password }) };
        link.Headers.Add("Cookie", GoogleTestFlow.Cookies(pending));
        var linked = await client.SendAsync(link);
        Assert.Equal(HttpStatusCode.OK, linked.StatusCode);
        var linkedAccess = Access(linked);
        var replay = await Reset(client, user, recovery, Secret());
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        NoSession(replay);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, linkedAccess)).StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(user.Id, (await db.ExternalLogins.SingleAsync(login => login.Subject == subject)).UserId);
    }

    [Fact]
    public async Task ConcurrentRecoveryRedemptionConsumesTokenAtMostOnce()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var user = await NewUser(factory);
        var recovery = await Recovery(factory, client, user);
        var passwords = new[] { Secret(), Secret() };
        var responses = await Task.WhenAll(passwords.Select(password => Reset(client, user, recovery, password)));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.All(responses, response => Assert.True(response.StatusCode is HttpStatusCode.OK or
            HttpStatusCode.Unauthorized or HttpStatusCode.Conflict,
            "Concurrent recovery must produce success or a controlled refusal, never a server error."));
        var winner = Array.FindIndex(responses, response => response.StatusCode == HttpStatusCode.OK);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.Users.SingleAsync(account => account.Id == user.Id);
        Assert.True(BCrypt.Net.BCrypt.Verify(passwords[winner], stored.PasswordHash),
            "The committed password must belong to the single successful request.");
        Assert.Null(stored.PasswordResetToken);
        Assert.Null(stored.ResetTokenExpires);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Reset(client, user, recovery, Secret())).StatusCode);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("signature")]
    [InlineData("unsigned")]
    [InlineData("expired")]
    public async Task InvalidJwtCannotReachInternalValidation(string fault)
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var access = await Login(client, await NewUser(factory));
        var decoded = new JwtSecurityTokenHandler().ReadJwtToken(access);
        var key = fault == "signature" ? RandomNumberGenerator.GetBytes(64) : Encoding.UTF8.GetBytes(SessionApiFactory.SigningKey);
        var jwt = new JwtSecurityToken(
            fault == "issuer" ? "untrusted-issuer" : decoded.Issuer,
            fault == "audience" ? "untrusted-audience" : decoded.Audiences.Single(),
            decoded.Claims.Where(claim => claim.Type is not JwtRegisteredClaimNames.Iss and not JwtRegisteredClaimNames.Aud
                and not JwtRegisteredClaimNames.Exp and not JwtRegisteredClaimNames.Nbf and not JwtRegisteredClaimNames.Iat),
            expires: fault == "expired" ? DateTime.UtcNow.AddMinutes(-2) : DateTime.UtcNow.AddMinutes(5),
            signingCredentials: fault == "unsigned" ? null : new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256));
        var response = await Validate(client, new JwtSecurityTokenHandler().WriteToken(jwt));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        NoSession(response);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, access)).StatusCode);
    }

    [Fact]
    public async Task OrdinaryUserCannotPromoteSelfOrAnotherUser()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var attacker = await NewUser(factory);
        var other = await NewUser(factory);
        var access = await Login(client, attacker);
        foreach (var target in new[] { attacker, other })
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/promover/email")
                { Content = JsonContent.Create(new { target.Email, role = "Admin", userId = target.Id }) };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(request)).StatusCode);
        }
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.All(await db.Users.Where(account => account.Id == attacker.Id || account.Id == other.Id).ToListAsync(),
            account => Assert.Equal("User", account.Role));
    }

    [Fact]
    public async Task RegistrationIgnoresProtectedIdentityAndSessionFields()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var other = await NewUser(factory);
        var email = $"massassignment.{Guid.NewGuid():N}@example.test";
        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email, password = Secret(), id = other.Id, role = "Admin", emailConfirmed = true,
            securityStamp = "client-controlled", deletedAt = DateTimeOffset.UtcNow,
            refreshTokens = new[] { new { sessionId = "client-controlled", expiryTime = DateTimeOffset.UtcNow.AddYears(1) } }
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        NoSession(response);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var created = await db.Users.SingleAsync(account => account.Email == email);
        Assert.NotEqual(other.Id, created.Id);
        Assert.Equal("User", created.Role);
        Assert.False(created.EmailConfirmed);
        Assert.Null(created.DeletedAt);
        Assert.True(created.SecurityStamp != "client-controlled");
        Assert.False(await db.RefreshTokens.AnyAsync(session => session.UserId == created.Id));
        Assert.Equal("User", (await db.Users.SingleAsync(account => account.Id == other.Id)).Role);
    }

    [Fact]
    public async Task ForeignIdentifiersCannotSelectAnotherProfileOrValidatedSubject()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var other = await NewUser(factory);
        var own = await NewUser(factory);
        var access = await Login(client, own);
        var profile = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/perfil?userId=" + other.Id +
            "&id=" + other.Id + "&email=" + Uri.EscapeDataString(other.Email));
        profile.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        profile.Headers.Add("X-User-ID", other.Id.ToString());
        var profileResponse = await client.SendAsync(profile);
        Assert.Equal(HttpStatusCode.OK, profileResponse.StatusCode);
        var body = await profileResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(body.GetProperty("id").GetInt64() == own.Id, "Profile selection must follow the authenticated identity.");
        var validation = new HttpRequestMessage(HttpMethod.Get, "/internal/auth/validate?sub=" + other.Id + "&userId=" + other.Id);
        validation.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        validation.Headers.Add("X-User-ID", other.Id.ToString());
        var validated = await client.SendAsync(validation);
        Assert.Equal(HttpStatusCode.OK, validated.StatusCode);
        var subject = await validated.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(subject.GetProperty("sub").GetString() == own.Id.ToString(), "Internal validation must ignore client-selected subjects.");
    }

    [Fact]
    public async Task SqlMetacharactersCannotBypassLocalAuthentication()
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var user = await NewUser(factory);
        foreach (var email in new[] { "security'OR'1'='1@example.test", "security\\'OR'1'='1@example.test", "security%27@example.test" })
        {
            var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = user.Password });
            Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest,
                "SQL metacharacters must be refused as credentials or invalid input.");
            NoSession(response);
        }
        var passwordInjection = await client.PostAsJsonAsync("/api/v1/auth/login", new { user.Email, password = "' OR '1'='1" });
        Assert.Equal(HttpStatusCode.Unauthorized, passwordInjection.StatusCode);
        NoSession(passwordInjection);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.True(await db.Users.AnyAsync(account => account.Id == user.Id && account.Email == user.Email && account.Role == "User"));
        Assert.False(await db.RefreshTokens.AnyAsync(session => session.UserId == user.Id));
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("signature")]
    [InlineData("expired")]
    public async Task InvalidOidcIdTokenCannotCreateIdentityOrSession(string fault)
    {
        await using var factory = new SecurityAuditApiFactory();
        using var client = Client(factory);
        var email = $"invalid.oidc.{Guid.NewGuid():N}@example.test";
        var start = await client.GetAsync("/api/v1/auth/google/login");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var query = QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        var code = Guid.NewGuid().ToString("N");
        using var wrongRsa = RSA.Create(2048);
        var signingKey = fault == "signature" ? new RsaSecurityKey(wrongRsa) { KeyId = "untrusted-key" } : factory.Backchannel.Key;
        var jwt = new JwtSecurityToken(
            fault == "issuer" ? "https://invalid.example.test" : "https://accounts.google.com",
            fault == "audience" ? "untrusted-client" : "test-client",
            [new Claim("sub", Guid.NewGuid().ToString("N")), new Claim("email", email),
                new Claim("email_verified", "true", ClaimValueTypes.Boolean), new Claim("nonce", query["nonce"].ToString()),
                new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)],
            expires: fault == "expired" ? DateTime.UtcNow.AddMinutes(-2) : DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));
        factory.Backchannel.Codes[code] = (new JwtSecurityTokenHandler().WriteToken(jwt), query["code_challenge"].ToString());
        var request = new HttpRequestMessage(HttpMethod.Get, GoogleAuthentication.Callback + "?code=" + code +
            "&state=" + Uri.EscapeDataString(query["state"].ToString()));
        request.Headers.Add("Cookie", GoogleTestFlow.Cookies(start));
        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.True(response.Headers.Location?.Query.Contains("auth_error=google_failed", StringComparison.Ordinal) == true);
        NoSession(response);
        using var scope = factory.Services.CreateScope();
        Assert.False(await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.AnyAsync(account => account.Email == email));
    }
}
