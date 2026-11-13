using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ApiAutenticacao.Authentication;

public static class GoogleAuthentication
{
    public const string Scheme = "Google";
    public const string PendingScheme = "GooglePending";
    public const string Callback = "/api/v1/auth/google/callback";
    public static void AddGoogleAuthentication(this IServiceCollection services)
    {
        services.AddScoped<AuthSettings>(); services.AddScoped<GoogleAccountService>();
        services.AddAuthentication().AddCookie(PendingScheme, options =>
        {
            options.Cookie.Name = "prevention.google.pending"; options.Cookie.HttpOnly = true;
            options.Cookie.Path = "/api/v1/auth/google"; options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(5); options.SlidingExpiration = false;
            options.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
            options.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
        }).AddOpenIdConnect(Scheme, _ => { });
        services.AddOptions<OpenIdConnectOptions>(Scheme).Configure<IConfiguration, IWebHostEnvironment>((options, configuration, env) =>
        {
            var settings = new AuthSettings(configuration, env);
            options.Authority = "https://accounts.google.com";
            var clientId = configuration["Authentication:Google:ClientId"];
            var clientSecret = configuration["Authentication:Google:ClientSecret"];
            // O middleware inicializa os handlers mesmo com Google desabilitado.
            options.ClientId = string.IsNullOrWhiteSpace(clientId) ? "google-disabled" : clientId;
            options.ClientSecret = string.IsNullOrWhiteSpace(clientSecret) ? "google-disabled" : clientSecret;
            options.CallbackPath = Callback; options.SignInScheme = PendingScheme;
            options.ResponseType = OpenIdConnectResponseType.Code; options.ResponseMode = OpenIdConnectResponseMode.Query;
            options.UsePkce = true; options.MapInboundClaims = false; options.SaveTokens = false;
            options.GetClaimsFromUserInfoEndpoint = false;
            options.Scope.Clear(); options.Scope.Add("openid"); options.Scope.Add("email"); options.Scope.Add("profile");
            options.TokenValidationParameters.ValidIssuers = ["https://accounts.google.com", "accounts.google.com"];
            options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
            options.CorrelationCookie.SameSite = SameSiteMode.Lax; options.NonceCookie.SameSite = SameSiteMode.Lax;
            options.CorrelationCookie.SecurePolicy = settings.SecureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            options.NonceCookie.SecurePolicy = options.CorrelationCookie.SecurePolicy;
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = context => { context.ProtocolMessage.RedirectUri = settings.Url(Callback); context.ProtocolMessage.Prompt = "select_account"; return Task.CompletedTask; },
                OnTicketReceived = async context =>
                {
                    var identity = GoogleAccountService.Identity(context.Principal);
                    context.HandleResponse();
                    if (identity == null) { context.Response.Redirect(settings.Url("/?auth_error=google_identity")); return; }
                    var service = context.HttpContext.RequestServices.GetRequiredService<GoogleAccountService>();
                    var credentials = await service.SignInAsync(identity, context.HttpContext.RequestAborted);
                    if (credentials == null)
                    {
                        await context.HttpContext.SignInAsync(PendingScheme, context.Principal!, new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(5), IsPersistent = false });
                        context.Response.Redirect(settings.Url("/vincular-google")); return;
                    }
                    SessionCookies.Write(context.HttpContext, settings, credentials.Value);
                    await context.HttpContext.SignOutAsync(PendingScheme);
                    context.Response.Redirect(settings.Url("/dashboard"));
                },
                OnRemoteFailure = context => { context.HandleResponse(); context.Response.Redirect(settings.Url("/?auth_error=google_failed")); return Task.CompletedTask; }
            };
        });
        services.AddOptions<CookieAuthenticationOptions>(PendingScheme).Configure<IConfiguration,IWebHostEnvironment>((options,config,env) =>
        { options.Cookie.SecurePolicy = new AuthSettings(config,env).SecureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest; });
    }
}
