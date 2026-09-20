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
using DotNetEnv;

//Console.WriteLine("teste 1");

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

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
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddValidatorsFromAssemblyContaining<RegisterDTOValidator>();
builder.Services.AddScoped<IValidator<ConfirmEmailDTO>, ConfirmEmailDTOValidator>();
builder.Services.AddScoped<IValidator<ResendConfirmationDTO>, ResendConfirmationDTOValidator>();
builder.Services.AddScoped<IValidator<ForgotPasswordDTO>, ForgotPasswordDTOValidator>();

var connectionString = builder.Configuration["ConnectionStrings:DefaultConnection"] ?? throw new InvalidOperationException("Connection string não configurada.");
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
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

var jwtKey = builder.Configuration["jwt:Key"] ?? throw new InvalidOperationException("Chave JWT não configurada.");
var jwtIssuer = builder.Configuration["jwt:Issuer"];
var jwtAudience = builder.Configuration["jwt:Audience"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
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
            if (string.IsNullOrEmpty(context.Token))
                context.Token = context.Request.Cookies["jwt"];
            return Task.CompletedTask;
        },
        OnTokenValidated = async context =>
        {
            var userIdClaim = context.Principal?.FindFirstValue(JwtRegisteredClaimNames.Sub)
                ?? context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            var stamp = context.Principal?.FindFirstValue("SecurityStamp");
            if (!long.TryParse(userIdClaim, out var userId) || string.IsNullOrWhiteSpace(stamp))
            {
                context.Fail("Token inválido.");
                return;
            }

            var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            var currentStamp = await db.Users
                .Where(user => user.Id == userId)
                .Select(user => user.SecurityStamp)
                .SingleOrDefaultAsync(context.HttpContext.RequestAborted);
            if (currentStamp != stamp)
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
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));

    options.AddPolicy("LoginRateLimit", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (dbContext.Database.IsRelational())
        dbContext.Database.Migrate();
    else
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
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapHealthChecks("/health");
app.MapControllers();

var endpoints = app.Services.GetRequiredService<EndpointDataSource>();
foreach (var ep in endpoints.Endpoints.OfType<RouteEndpoint>())
{
    var verbos = ep.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? new List<string>();
    Console.WriteLine($"[ROTA-REAL] {string.Join(",", verbos)} -> {ep.RoutePattern.RawText}");
}

app.Run();

public partial class Program { }