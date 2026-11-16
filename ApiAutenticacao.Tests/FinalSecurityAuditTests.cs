using System.Net;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiAutenticacao.Authentication;
using ApiAutenticacao.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Models;

namespace ApiAutenticacao.Tests;

public sealed class RotatedKeyApiFactory : GoogleApiFactory
{
    private readonly string signingKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            new Dictionary<string, string?> { ["jwt:Key"] = signingKey }));
    }
}

// MySQL auth_test only, enforced by SessionApiFactory. No real identities, e-mail,
// external OIDC requests, credentials in output, or persistent environment changes.
public sealed class FinalSecurityAuditTests
{
    private sealed record Fixture(long Id, string Email, string Password, string Hash, string Stamp);
    private sealed record Session(string Jwt, string Refresh);
    private static string Secret() => Guid.NewGuid().ToString("N") + "!";
    private static HttpClient Client(GoogleApiFactory factory) => factory.CreateClient(new()
        { HandleCookies = false, AllowAutoRedirect = false });
    private static async Task<Fixture> User(GoogleApiFactory factory, bool confirmed = true, bool locked = false)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var password = Secret();
        var user = new User { Email = $"final-audit.{Guid.NewGuid():N}@example.test",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password, 4), EmailConfirmed = confirmed,
            AccessFailedCount = locked ? 5 : 0, LockoutEnd = locked ? DateTimeOffset.UtcNow.AddMinutes(15) : null };
        db.Users.Add(user); await db.SaveChangesAsync();
        return new(user.Id, user.Email, password, user.PasswordHash!, user.SecurityStamp);
    }
    private static Session Cookies(HttpResponseMessage response)
    {
        var pairs = GoogleTestFlow.Cookies(response).Split("; ");
        string Read(string name) => pairs.Single(p => p.StartsWith(name + "=", StringComparison.Ordinal))[(name.Length + 1)..];
        return new(Read("jwt"), Read("refreshToken"));
    }
    private static void NoSession(HttpResponseMessage response) => Assert.False(
        response.Headers.TryGetValues("Set-Cookie", out var values) && values.Any(v => v.StartsWith("jwt=", StringComparison.Ordinal)),
        "A public acknowledgement or rejection must not issue an authenticated session.");
    private static async Task<Session> Login(HttpClient client, Fixture user)
    {
        using var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { user.Email, user.Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); return Cookies(response);
    }
    private static Task<HttpResponseMessage> Authorized(HttpClient client, string jwt, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        if (body != null) request.Content = JsonContent.Create(body);
        return client.SendAsync(request);
    }
    private static Task<HttpResponseMessage> Validate(HttpClient client, string jwt) =>
        Authorized(client, jwt, HttpMethod.Get, "/internal/auth/validate");
    private static Task<HttpResponseMessage> Refresh(HttpClient client, string value, string action = "refresh")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/" + action);
        request.Headers.Add("Cookie", "refreshToken=" + value); return client.SendAsync(request);
    }

    [Fact]
    public async Task RegistrationAcknowledgementDoesNotRevealOrModifyExistingIdentity()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var existing = await User(factory);
        var freshEmail = $"final-register.{Guid.NewGuid():N}@example.test";
        var fresh = await client.PostAsJsonAsync("/api/v1/auth/register", new { email = freshEmail, password = Secret() });
        var repeated = await client.PostAsJsonAsync("/api/v1/auth/register", new { email = existing.Email, password = Secret() });
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        Assert.Equal(HttpStatusCode.OK, repeated.StatusCode);
        Assert.True(await fresh.Content.ReadAsStringAsync() == await repeated.Content.ReadAsStringAsync(), "Public registration bodies must match.");
        NoSession(fresh); NoSession(repeated);
        using var scope = factory.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.Users.SingleAsync(u => u.Id == existing.Id);
        Assert.True(stored.PasswordHash == existing.Hash && stored.SecurityStamp == existing.Stamp && stored.EmailConfirmed,
            "An acknowledged duplicate must not alter the existing account.");
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == existing.Email));
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == freshEmail));
    }

    [Fact]
    public async Task ResendAcknowledgementDoesNotRevealAccountOrConfirmationState()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var confirmed = await User(factory); var pending = await User(factory, confirmed: false);
        var replies = new List<HttpResponseMessage>();
        foreach (var email in new[] { confirmed.Email, pending.Email, $"absent.{Guid.NewGuid():N}@example.test" })
            replies.Add(await client.PostAsJsonAsync("/api/v1/auth/resend-confirmation", new { email }));
        Assert.All(replies, reply => Assert.Equal(HttpStatusCode.OK, reply.StatusCode));
        var bodies = await Task.WhenAll(replies.Select(r => r.Content.ReadAsStringAsync()));
        Assert.True(bodies.Distinct().Count() == 1, "Resend responses must be generic.");
        foreach (var response in replies) NoSession(response);
        using var scope = factory.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.Users.SingleAsync(u => u.Id == confirmed.Id);
        Assert.True(stored.EmailConfirmed && stored.PasswordHash == confirmed.Hash && stored.SecurityStamp == confirmed.Stamp,
            "Resending must not change a confirmed identity.");
    }

    [Fact]
    public async Task RegistrationForDeletedIdentityIsGenericWithoutReactivation()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var user = await User(factory); var session = await Login(client, user);
        Assert.Equal(HttpStatusCode.OK, (await Authorized(client, session.Jwt, HttpMethod.Delete, "/api/v1/auth/delete-account")).StatusCode);
        var reply = await client.PostAsJsonAsync("/api/v1/auth/register", new { user.Email, password = Secret() });
        Assert.Equal(HttpStatusCode.OK, reply.StatusCode); NoSession(reply);
        using var scope = factory.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == user.Id);
        Assert.NotNull(stored.DeletedAt);
        Assert.True(stored.PasswordHash == user.Hash, "A deleted identity must never be replaced or reactivated by registration.");
        Assert.Equal(1, await db.Users.IgnoreQueryFilters().CountAsync(u => u.Email == user.Email));
    }

    [Fact]
    public async Task WrongUnknownAndLockedLoginsUseTheSameGenericResponse()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var known = await User(factory); var locked = await User(factory, locked: true);
        var replies = new List<HttpResponseMessage>();
        foreach (var email in new[] { known.Email, locked.Email, $"absent.{Guid.NewGuid():N}@example.test" })
            replies.Add(await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = Secret() }));
        Assert.All(replies, reply => Assert.Equal(HttpStatusCode.Unauthorized, reply.StatusCode));
        var bodies = await Task.WhenAll(replies.Select(r => r.Content.ReadAsStringAsync()));
        Assert.True(bodies.Distinct().Count() == 1, "Login refusals must be generic.");
        foreach (var response in replies) NoSession(response);
    }

    [Fact]
    public async Task PasswordChangeLimitIsPerIdentityAndWrongAttemptsPreserveSessions()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var a = await User(factory); var b = await User(factory);
        var sa = await Login(client, a); var sb = await Login(client, b);
        for (var n = 0; n < 5; n++)
            Assert.Equal(HttpStatusCode.BadRequest, (await Authorized(client, sa.Jwt, HttpMethod.Post, "/api/v1/auth/change-password",
                new { senhaAtual = Secret(), novaSenha = Secret() })).StatusCode);
        var limited = await Authorized(client, sa.Jwt, HttpMethod.Post, "/api/v1/auth/change-password",
            new { senhaAtual = Secret(), novaSenha = Secret() });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        NoSession(limited);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>(); var stored = await db.Users.SingleAsync(u => u.Id == a.Id);
            Assert.True(stored.PasswordHash == a.Hash && stored.SecurityStamp == a.Stamp && stored.AccessFailedCount == 0 && stored.LockoutEnd == null,
                "Wrong authenticated attempts must not change credentials or lock the identity.");
            Assert.Equal(1, await db.RefreshTokens.CountAsync(t => t.UserId == a.Id));
        }
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, sa.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Authorized(client, sb.Jwt, HttpMethod.Post, "/api/v1/auth/change-password",
            new { senhaAtual = b.Password, novaSenha = Secret() })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(client, sb.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(client, sa.Refresh, "logout")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(client, sa.Jwt)).StatusCode);
    }

    [Fact]
    public async Task SigningKeyRotationInvalidatesOldJwtAndRefreshWithoutDeletingAccount()
    {
        await using var original = new GoogleApiFactory(); using var firstClient = Client(original);
        var user = await User(original); var session = await Login(firstClient, user);
        await using var rotated = new RotatedKeyApiFactory(); using var nextClient = Client(rotated);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(nextClient, session.Jwt)).StatusCode);
        var replay = await Refresh(nextClient, session.Refresh);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        NoSession(replay);
        using (var scope = rotated.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>(); var stored = await db.Users.SingleAsync(u => u.Id == user.Id);
            Assert.True(stored.PasswordHash == user.Hash && stored.SecurityStamp == user.Stamp, "Key rotation must preserve account credentials.");
            Assert.Equal(1, await db.RefreshTokens.CountAsync(t => t.UserId == user.Id));
        }
        var fresh = await Login(nextClient, user);
        Assert.Equal(HttpStatusCode.OK, (await Validate(nextClient, fresh.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(nextClient, fresh.Refresh)).StatusCode);
    }

    [Fact]
    public async Task ReplayAndArbitraryRefreshCannotRevokeAnotherLegitimateSession()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var user = await User(factory); var initial = await Login(client, user); var other = await Login(client, user);
        var response = await Refresh(client, initial.Refresh); Assert.Equal(HttpStatusCode.OK, response.StatusCode); var current = Cookies(response);
        factory.Clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(client, initial.Refresh)).StatusCode);
        var pieces = current.Refresh.Split('.'); pieces[2] = new string(pieces[2][0] == 'A' ? 'B' : 'A', 43);
        var invented = string.Join('.', pieces);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(client, invented)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(client, invented, "logout")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, current.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, other.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(client, current.Refresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(client, other.Refresh)).StatusCode);
    }

    [Fact]
    public async Task CompromisedFixtureKeyCanForgeRoleButRotationRejectsIt()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var owner = await User(factory); var target = await User(factory); var session = await Login(client, owner);
        var body = new { email = target.Email };
        Assert.Equal(HttpStatusCode.Forbidden, (await Authorized(client, session.Jwt, HttpMethod.Post, "/api/v1/auth/promover/email", body)).StatusCode);
        var decoded = new JwtSecurityTokenHandler().ReadJwtToken(session.Jwt);
        var claims = decoded.Claims.Where(c => c.Type != ClaimTypes.Role && c.Type != "role" &&
            c.Type is not JwtRegisteredClaimNames.Iss and not JwtRegisteredClaimNames.Aud and not JwtRegisteredClaimNames.Exp)
            .Append(new Claim(ClaimTypes.Role, "Admin"));
        var token = new JwtSecurityToken(decoded.Issuer, decoded.Audiences.Single(), claims,
            expires: DateTime.UtcNow.AddMinutes(5), signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SessionApiFactory.SigningKey)), SecurityAlgorithms.HmacSha256));
        // Only the public test fixture key is used; never an actual environment key.
        var forged = new JwtSecurityTokenHandler().WriteToken(token);
        Assert.Equal(HttpStatusCode.OK, (await Authorized(client, forged, HttpMethod.Post, "/api/v1/auth/promover/email", body)).StatusCode);
        await using var rotated = new RotatedKeyApiFactory(); using var next = Client(rotated);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(next, forged)).StatusCode);
        var fresh = await Login(next, owner);
        Assert.Equal(HttpStatusCode.Forbidden, (await Authorized(next, fresh.Jwt, HttpMethod.Post, "/api/v1/auth/promover/email", body)).StatusCode);
    }

    [Fact]
    public async Task AccountDeletionUsesAuthenticatedIdentityAndPreservesOtherUser()
    {
        await using var factory = new GoogleApiFactory(); using var client = Client(factory);
        var a = await User(factory); var b = await User(factory); var sa = await Login(client, a); var sb = await Login(client, b);
        var request = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/auth/delete-account?userId=" + b.Id + "&email=" + Uri.EscapeDataString(b.Email));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sa.Jwt);
        request.Headers.Add("X-User-ID", b.Id.ToString());
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(client, sa.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Validate(client, sb.Jwt)).StatusCode);
        using var scope = factory.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.NotNull((await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == a.Id)).DeletedAt);
        Assert.Null((await db.Users.SingleAsync(u => u.Id == b.Id)).DeletedAt);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public void ShortSigningKeysFailBeforeServingRequests(string environment)
    {
        var env = new Mock<IWebHostEnvironment>(); env.SetupGet(e => e.EnvironmentName).Returns(environment);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["PublicBaseUrl"] = "https://finance.example.test", ["jwt:Key"] = "short", ["Proxy:SharedKey"] = new string('x', 64),
          ["Authentication:Mode"] = "Hybrid", ["Authentication:Google:Enabled"] = "false" }).Build();
        var failure = Assert.Throws<InvalidOperationException>(() => new AuthSettings(config, env.Object).Validate());
        Assert.Contains("JWT_KEY", failure.Message, StringComparison.Ordinal);
    }
}
