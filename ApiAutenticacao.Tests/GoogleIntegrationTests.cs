using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApiAutenticacao.Authentication;
using ApiAutenticacao.Data;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Models;

namespace ApiAutenticacao.Tests;

public class GoogleApiFactory : SessionApiFactory
{
    public FakeGoogle Backchannel { get; } = new();
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string,string?>
        {
            ["Authentication:Google:Enabled"] = "true", ["Authentication:Google:ClientId"] = "test-client",
            ["Authentication:Google:ClientSecret"] = "test-secret", ["PublicBaseUrl"] = "http://localhost"
        }));
        builder.ConfigureTestServices(services => services.PostConfigure<OpenIdConnectOptions>(GoogleAuthentication.Scheme, options =>
        {
            options.Configuration = new OpenIdConnectConfiguration
            { Issuer = "https://accounts.google.com", AuthorizationEndpoint = "https://accounts.google.com/authorize", TokenEndpoint = "https://oauth2.googleapis.com/token" };
            options.Configuration.SigningKeys.Add(Backchannel.Key);
            options.ConfigurationManager = new Microsoft.IdentityModel.Protocols.StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            options.Backchannel = new HttpClient(Backchannel);
        }));
    }
}
public sealed class FakeGoogle : HttpMessageHandler
{
    public RsaSecurityKey Key { get; } = new(RSA.Create(2048)) { KeyId = "test-google-key" };
    public ConcurrentDictionary<string,(string Token,string Challenge)> Codes { get; } = new();
    public int Calls;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
    {
        Interlocked.Increment(ref Calls);
        var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(ct));
        if (request.RequestUri!.AbsoluteUri != "https://oauth2.googleapis.com/token" || !Codes.TryRemove(form["code"].ToString(),out var record)) return new(HttpStatusCode.BadRequest);
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString())));
        Assert.Equal(record.Challenge,challenge);
        Assert.Equal("test-client",form["client_id"].ToString());
        Assert.Equal("http://localhost"+GoogleAuthentication.Callback,form["redirect_uri"].ToString());
        return new(HttpStatusCode.OK) { Content = JsonContent.Create(new { access_token="test-only-access",token_type="Bearer",expires_in=300,id_token=record.Token }) };
    }
}
public sealed class GoogleIntegrationTests : IClassFixture<GoogleApiFactory>
{
    private readonly GoogleApiFactory factory;
    private readonly HttpClient client;
    public GoogleIntegrationTests(GoogleApiFactory factory) { this.factory=factory;client=factory.CreateClient(new(){HandleCookies=false,AllowAutoRedirect=false}); }
    private static string Cookies(HttpResponseMessage response) => response.Headers.TryGetValues("Set-Cookie",out var values) ? string.Join("; ",values.Select(v=>v.Split(';')[0])) : "";
    private async Task<HttpResponseMessage> SignIn(string sub,string email,string? nonceOverride=null,bool verified=true)
    {
        var start=await client.GetAsync("/api/v1/auth/google/login");Assert.Equal(HttpStatusCode.Redirect,start.StatusCode);
        var query=QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        Assert.Equal("code",query["response_type"].ToString());Assert.Equal("S256",query["code_challenge_method"].ToString());
        var code=Guid.NewGuid().ToString("N");
        var jwt=new JwtSecurityToken("https://accounts.google.com","test-client",[
            new Claim("sub",sub),new Claim("email",email),new Claim("email_verified",verified?"true":"false",ClaimValueTypes.Boolean),new Claim("nonce",nonceOverride??query["nonce"].ToString()),
            new Claim("iat",DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64)
        ],expires:DateTime.UtcNow.AddMinutes(5),signingCredentials:new SigningCredentials(factory.Backchannel.Key,SecurityAlgorithms.RsaSha256));
        factory.Backchannel.Codes[code]=(new JwtSecurityTokenHandler().WriteToken(jwt),query["code_challenge"].ToString());
        var request=new HttpRequestMessage(HttpMethod.Get,GoogleAuthentication.Callback+"?code="+code+"&state="+Uri.EscapeDataString(query["state"].ToString()));
        request.Headers.Add("Cookie",Cookies(start));return await client.SendAsync(request);
    }
    [Fact]
    public async Task GoogleLoginCreatesPasswordlessUserAndReusesInternalId()
    {
        var sub=Guid.NewGuid().ToString("N");var email=$"google.{sub}@example.test";
        var first=await SignIn(sub,email);Assert.Equal("http://localhost/dashboard",first.Headers.Location?.AbsoluteUri);Assert.Contains("jwt=",Cookies(first));
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var account=await db.Users.SingleAsync(u=>u.Email==email);Assert.Null(account.PasswordHash);var id=account.Id;
        var access=Cookies(first).Split("; ").Single(c=>c.StartsWith("jwt=")).Substring(4);
        Assert.Equal(id.ToString(),new JwtSecurityTokenHandler().ReadJwtToken(access).Subject);
        var validate=new HttpRequestMessage(HttpMethod.Get,"/internal/auth/validate");validate.Headers.Authorization=new AuthenticationHeaderValue("Bearer",access);
        Assert.Equal(HttpStatusCode.OK,(await client.SendAsync(validate)).StatusCode);
        var again=await SignIn(sub,email);Assert.Contains("jwt=",Cookies(again));
        Assert.Equal(id,(await db.ExternalLogins.SingleAsync(x=>x.Subject==sub)).UserId);
    }
    [Fact]
    public async Task ExistingEmailRequiresProofAndLinkPreservesUserId()
    {
        var email=$"legacy.{Guid.NewGuid():N}@example.test";
        long id;using(var scope=factory.Services.CreateScope()){var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var u=new User{Email=email,PasswordHash=BCrypt.Net.BCrypt.HashPassword("Existing123!",4),EmailConfirmed=true};db.Users.Add(u);await db.SaveChangesAsync();id=u.Id;}
        var sub=Guid.NewGuid().ToString("N");var callback=await SignIn(sub,email);
        Assert.Equal("http://localhost/vincular-google",callback.Headers.Location?.AbsoluteUri);Assert.DoesNotContain("jwt=",Cookies(callback));
        using(var scope=factory.Services.CreateScope()){Assert.False(await scope.ServiceProvider.GetRequiredService<AppDbContext>().ExternalLogins.AnyAsync(x=>x.Subject==sub));}
        var wrong=new HttpRequestMessage(HttpMethod.Post,"/api/v1/auth/google/link"){Content=JsonContent.Create(new{password="wrong"})};wrong.Headers.Add("Cookie",Cookies(callback));Assert.Equal(HttpStatusCode.Unauthorized,(await client.SendAsync(wrong)).StatusCode);
        var link=new HttpRequestMessage(HttpMethod.Post,"/api/v1/auth/google/link"){Content=JsonContent.Create(new{password="Existing123!"})};link.Headers.Add("Cookie",Cookies(callback));var result=await client.SendAsync(link);Assert.Equal(HttpStatusCode.OK,result.StatusCode);Assert.Contains("jwt=",Cookies(result));
        using(var scope=factory.Services.CreateScope()){var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();Assert.Equal(id,(await db.ExternalLogins.SingleAsync(x=>x.Subject==sub)).UserId);Assert.Equal(1,await db.Users.CountAsync(u=>u.Email==email));}
    }
    [Fact]
    public async Task InvalidStateDoesNotRedeemCodeOrIssueJwt()
    {
        var before=factory.Backchannel.Calls;var response=await client.GetAsync(GoogleAuthentication.Callback+"?code=untrusted&state=invalid");
        Assert.Equal(HttpStatusCode.Redirect,response.StatusCode);Assert.Contains("auth_error=google_failed",response.Headers.Location!.OriginalString);Assert.DoesNotContain("jwt=",Cookies(response));Assert.Equal(before,factory.Backchannel.Calls);
    }
    [Fact]
    public async Task MissingCorrelationCookieIsRejected()
    {
        var start=await client.GetAsync("/api/v1/auth/google/login");var query=QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        var response=await client.GetAsync(GoogleAuthentication.Callback+"?code=untrusted&state="+Uri.EscapeDataString(query["state"].ToString()));
        Assert.Contains("auth_error=google_failed",response.Headers.Location!.OriginalString);Assert.DoesNotContain("jwt=",Cookies(response));
    }
    [Fact]
    public async Task WrongNonceAndUnverifiedEmailCannotAuthenticate()
    {
        foreach(var verified in new[]{true,false}){var result=await SignIn(Guid.NewGuid().ToString("N"),$"invalid.{Guid.NewGuid():N}@example.test",verified?"wrong-nonce":null,verified);Assert.DoesNotContain("jwt=",Cookies(result));Assert.Contains(verified?"auth_error=google_failed":"auth_error=google_identity",result.Headers.Location!.OriginalString);}
    }
}

public sealed class GoogleOnlyApiFactory : GoogleApiFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_,config)=>config.AddInMemoryCollection(new Dictionary<string,string?> { ["Authentication:Mode"]="GoogleOnly" }));
    }
}
public sealed class GoogleOnlyIntegrationTests : IClassFixture<GoogleOnlyApiFactory>
{
    private readonly HttpClient client;
    public GoogleOnlyIntegrationTests(GoogleOnlyApiFactory factory) => client=factory.CreateClient(new(){AllowAutoRedirect=false});
    [Fact]
    public async Task PasswordAndSmtpEndpointsAreRetiredWhileGoogleIsAvailable()
    {
        var providers=await client.GetFromJsonAsync<JsonElement>("/api/v1/auth/providers");
        Assert.True(providers.GetProperty("google").GetBoolean());Assert.False(providers.GetProperty("local").GetBoolean());
        foreach(var action in new[]{"login","register","confirm-email","resend-confirmation","forgot-password","reset-password","change-password"})
            Assert.Equal(HttpStatusCode.Gone,(await client.PostAsJsonAsync("/api/v1/auth/"+action,new{})).StatusCode);
        foreach(var path in new[]{"/api/v1/Auth/login/","/API/V1/AUTH/LOGIN","/api/v1/auth/register/"})
            Assert.Equal(HttpStatusCode.Gone,(await client.PostAsJsonAsync(path,new{})).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await client.PostAsJsonAsync("/api/v1.0/auth/login",new{})).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect,(await client.GetAsync("/api/v1/auth/google/login")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.PostAsJsonAsync("/api/v1/auth/refresh",new{})).StatusCode);
    }
}
