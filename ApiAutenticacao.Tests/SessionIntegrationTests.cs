using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using ApiAutenticacao.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Models;

namespace ApiAutenticacao.Tests;

public sealed class SessionIntegrationTests : IClassFixture<SessionApiFactory>
{
    private readonly SessionApiFactory factory;
    private readonly HttpClient client;
    private const string Password = "SessionTest123!";
    private sealed record Tokens(string Jwt, string Refresh);

    public SessionIntegrationTests(SessionApiFactory factory)
    {
        this.factory = factory;
        factory.Clock.Reset();
        client = factory.CreateClient(new() { HandleCookies = false, AllowAutoRedirect = false });
    }
    private async Task<string> NewUser()
    {
        var email = $"session.{Guid.NewGuid():N}@example.test";
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Add(new User { Email = email, PasswordHash = BCrypt.Net.BCrypt.HashPassword(Password, 4), EmailConfirmed = true });
        await db.SaveChangesAsync();
        return email;
    }
    private static Tokens Cookies(HttpResponseMessage response)
    {
        var cookies = response.Headers.GetValues("Set-Cookie").ToList();
        string Read(string name) => cookies.Single(c => c.StartsWith(name + "=", StringComparison.Ordinal)).Split(';')[0].Split('=', 2)[1];
        Assert.All(cookies, c => Assert.Contains("httponly", c, StringComparison.OrdinalIgnoreCase));
        return new Tokens(Read("jwt"), Read("refreshToken"));
    }
    private async Task<Tokens> Login(string email)
    {
        var response = await client.PostAsJsonAsync("/api/v1/Auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Cookies(response);
    }
    private Task<HttpResponseMessage> Refresh(string value)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/Auth/refresh");
        request.Headers.Add("Cookie", "refreshToken=" + value);
        return client.SendAsync(request);
    }
    private Task<HttpResponseMessage> Validate(string jwt)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/internal/auth/validate");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client.SendAsync(request);
    }
    private async Task Logout(Tokens tokens, bool bearerOnly = false)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/Auth/logout");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.Jwt);
        if (!bearerOnly) request.Headers.Add("Cookie", "refreshToken=" + tokens.Refresh);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
    }
    [Fact]
    public async Task LogoutRevokesCopiedJwtAndKeepsOtherDeviceActive()
    {
        var email = await NewUser(); var a = await Login(email); var b = await Login(email);
        Assert.Equal(HttpStatusCode.OK, (await Validate(a.Jwt)).StatusCode);
        await Logout(a);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(a.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(a.Refresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Validate(b.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(b.Refresh)).StatusCode);
    }
    [Fact]
    public async Task LogoutWithBearerOnlyRevokesTheSession()
    {
        var tokens = await Login(await NewUser());
        await Logout(tokens, bearerOnly: true);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(tokens.Jwt)).StatusCode);
    }
    [Fact]
    public async Task ConcurrentRefreshesReturnSameRotatedToken()
    {
        var tokens = await Login(await NewUser());
        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Refresh(tokens.Refresh)));
        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        var rotated = responses.Select(Cookies).ToArray();
        Assert.Single(rotated.Select(t => t.Refresh).Distinct());
        Assert.NotEqual(tokens.Refresh, rotated[0].Refresh);
        foreach (var token in rotated) Assert.Equal(HttpStatusCode.OK, (await Validate(token.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(rotated[0].Refresh)).StatusCode);
    }
    [Fact]
    public async Task PreviousRefreshExpiresAfterGraceAndLogoutRevokesRotatedSession()
    {
        var tokens = await Login(await NewUser());
        var current = Cookies(await Refresh(tokens.Refresh));
        factory.Clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tokens.Refresh)).StatusCode);
        var next = Cookies(await Refresh(current.Refresh));
        await Logout(next);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(tokens.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(current.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(next.Refresh)).StatusCode);
    }
    [Fact]
    public async Task ExpiredJwtIsRejectedButRefreshStillWorks()
    {
        var tokens = await Login(await NewUser());
        var decoded = new JwtSecurityTokenHandler().ReadJwtToken(tokens.Jwt);
        var expired = new JwtSecurityToken(decoded.Issuer, decoded.Audiences.Single(), decoded.Claims,
            expires: DateTime.UtcNow.AddMinutes(-1), signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SessionApiFactory.SigningKey)), SecurityAlgorithms.HmacSha256));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(new JwtSecurityTokenHandler().WriteToken(expired))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(tokens.Refresh)).StatusCode);
    }
    [Fact]
    public async Task ExpiredSessionCannotValidateOrRefresh()
    {
        var tokens = await Login(await NewUser()); factory.Clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(tokens.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(tokens.Refresh)).StatusCode);
    }
    [Fact]
    public async Task LogoutAllRevokesBothJwtAndRefreshOfEveryDevice()
    {
        var email = await NewUser(); var a = await Login(email); var b = await Login(email);
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/Auth/logout-all");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", a.Jwt);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
        foreach (var t in new[] { a, b })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(t.Jwt)).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(t.Refresh)).StatusCode);
        }
    }
    [Fact]
    public async Task PasswordChangeRevokesAllSessionsAndRefreshes()
    {
        var email = await NewUser(); var a = await Login(email); var b = await Login(email);
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/Auth/change-password")
        { Content = JsonContent.Create(new { senhaAtual = Password, novaSenha = "ChangedSession123!" }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", a.Jwt);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(b.Jwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(b.Refresh)).StatusCode);
    }
    [Fact]
    public async Task TamperedAndLegacyTokensCannotStartSessions()
    {
        var tokens = await Login(await NewUser());
        var parts = tokens.Refresh.Split('.');
        parts[2] = new string('A', 43);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(string.Join('.', parts))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh("legacy-token" )).StatusCode);
        var decoded = new JwtSecurityTokenHandler().ReadJwtToken(tokens.Jwt);
        var legacy = new JwtSecurityToken(decoded.Issuer, decoded.Audiences.Single(), decoded.Claims.Where(c => c.Type != "sid"),
            expires: DateTime.UtcNow.AddMinutes(15), signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SessionApiFactory.SigningKey)), SecurityAlgorithms.HmacSha256));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Validate(new JwtSecurityTokenHandler().WriteToken(legacy))).StatusCode);
    }
}
