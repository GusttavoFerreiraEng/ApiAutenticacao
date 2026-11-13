using System.Text;
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Threading.RateLimiting;
using FluentValidation;
using ApiAutenticacao.Services;
using ApiAutenticacao.Validations;
using ApiAutenticacao.DTOs;
using Models;
using Microsoft.AspNetCore.HttpOverrides;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Data;
using ApiAutenticacao.Middlewares;
using ApiAutenticacao.Repositories;
using Asp.Versioning;
using ApiAutenticacao.Authentication;
using Microsoft.AspNetCore.DataProtection;

//Console.WriteLine("teste 1");

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddJsonConsole(options => { options.IncludeScopes = true; options.TimestampFormat = "yyyy-MM-ddTHH:mm:ssZ"; options.UseUtcTimestamp = true; });


builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
});

builder.Services.AddHealthChecks()
    .AddCheck("database", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy())
    .AddDbContextCheck<AppDbContext>();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddGoogleAuthentication();
var keyPath = builder.Configuration["DataProtection:KeyPath"];
if (!string.IsNullOrWhiteSpace(keyPath))
    builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyPath)).SetApplicationName("PreventionFinance");
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddValidatorsFromAssemblyContaining<RegisterDTOValidator>();
builder.Services.AddScoped<IValidator<ConfirmEmailDTO>, ConfirmEmailDTOValidator>();
builder.Services.AddScoped<IValidator<ResendConfirmationDTO>, ResendConfirmationDTOValidator>();
builder.Services.AddScoped<IValidator<ForgotPasswordDTO>, ForgotPasswordDTOValidator>();

builder.Services.AddDbContext<AppDbContext>((services, options) =>
{
    var connectionString = services.GetRequiredService<IConfiguration>()["ConnectionStrings:DefaultConnection"]
        ?? throw new InvalidOperationException("Connection string não configurada.");
    options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 0)));
});

var frontEndUrl = builder.Configuration["FrontendUrl"];
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        if (!string.IsNullOrWhiteSpace(frontEndUrl))
            policy.WithOrigins(frontEndUrl);
        policy.AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

builder.Services.AddHostedService<TokenCleanupService>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer();

builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
.Configure<IConfiguration, IWebHostEnvironment>((options, configuration, environment) =>
{
    var jwtKey = configuration["jwt:Key"] ?? throw new InvalidOperationException("Chave JWT não configurada.");
    var jwtIssuer = configuration["jwt:Issuer"];
    var jwtAudience = configuration["jwt:Audience"];
    options.RequireHttpsMetadata = !environment.IsDevelopment();
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtAudience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            if (!context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                context.Token = context.Request.Cookies["jwt"];
            return Task.CompletedTask;
        },
        OnTokenValidated = async context =>
        {
            var userIdClaim = context.Principal?.FindFirstValue(JwtRegisteredClaimNames.Sub)
                ?? context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            var stamp = context.Principal?.FindFirstValue("SecurityStamp");
            var sid = context.Principal?.FindFirstValue("sid") ?? context.Principal?.FindFirstValue(ClaimTypes.Sid);
            if (!long.TryParse(userIdClaim, out var userId) || string.IsNullOrWhiteSpace(stamp) || string.IsNullOrWhiteSpace(sid))
            {
                context.Fail("Token inválido.");
                return;
            }

            var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            var now = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
            var active = await db.RefreshTokens.AnyAsync(session => session.UserId == userId &&
                session.SessionId == sid && session.ExpiryTime > now && session.User.SecurityStamp == stamp,
                context.HttpContext.RequestAborted);
            if (!active)
                context.Fail("Token revogado.");
        }
    };
});

builder.Services.AddSwaggerGen(opcoes =>
{
    opcoes.SwaggerDoc("v1", new OpenApiInfo { Title = "API Autenticacao", Version = "v1" });
    opcoes.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o JWT desta maneira: Bearer {seu_token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    opcoes.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.FindFirst("sub")?.Value ?? httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = builder.Configuration.GetValue<int>("RateLimits:GlobalPerMinute", 100),
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));

    options.AddPolicy("LoginRateLimit", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = builder.Configuration.GetValue<int>("RateLimits:LoginPerMinute", 5),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    options.AddPolicy("ExternalLoginRateLimit", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("ExternalLinkRateLimit", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 5, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    scope.ServiceProvider.GetRequiredService<AuthSettings>().Validate();
    if (args.Contains("--migrate")) { await dbContext.Database.MigrateAsync(); return; }
    if (dbContext.Database.IsRelational() && builder.Configuration.GetValue<bool>("Database:AutoMigrate", !app.Environment.IsProduction()))
        dbContext.Database.Migrate();
    else if (!dbContext.Database.IsRelational())
        dbContext.Database.EnsureCreated();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseExceptionHandler("/error");

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    // context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none';");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';");
    await next();
});

app.UseStaticFiles();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.InjectStylesheet("/swagger-dark.css"); 
    });

}
else
{
    app.UseHsts();
}

app.UseCors("CorsPolicy");
app.Use(async (context, next) =>
{
    if (TrustedProxy.TryClientIp(context.Request, builder.Configuration["Proxy:SharedKey"], out var clientIp))
        context.Connection.RemoteIpAddress = clientIp;
    await next();
});
app.UseAuthentication();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    var action = context.GetEndpoint()?.Metadata.GetMetadata<Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor>();
    var legacy = new[] { "Login", "Register", "ConfirmEmail", "ResendConfirmation", "ForgotPassword", "ResetPassword", "ChangePassword" };
    // Metadados cobrem versões equivalentes (v1/v1.0), caixa e barra final da rota.
    if (!context.RequestServices.GetRequiredService<AuthSettings>().LocalEnabled && action?.ControllerName == "Auth" &&
        legacy.Contains(action.ActionName, StringComparer.OrdinalIgnoreCase))
    { context.Response.StatusCode = 410; await context.Response.WriteAsJsonAsync(new { error = "Acesso por senha encerrado. Entre com Google." }); return; }
    await next();
});
app.UseAuthorization();

app.MapHealthChecks("/health").DisableRateLimiting();
app.MapControllers();

var endpoints = app.Services.GetRequiredService<EndpointDataSource>();
foreach (var ep in endpoints.Endpoints.OfType<RouteEndpoint>())
{
    var verbos = ep.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? new List<string>();
    Console.WriteLine($"[ROTA-REAL] {string.Join(",", verbos)} -> {ep.RoutePattern.RawText}");
}

app.Run();

public partial class Program { }
