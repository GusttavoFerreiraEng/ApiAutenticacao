using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using FluentValidation;
using ApiAutenticacao.Services;
using ApiAutenticacao.Validations;
using Models;
using ApiAutenticacao.Data;
using ApiAutenticacao.Middlewares;

var builder = WebApplication.CreateBuilder(args);

// Configura os serviços principais da aplicação: controllers, health checks, persistência, validação e CORS.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Health checks básicos para monitorar a aplicação em produção.
builder.Services.AddHealthChecks()
    .AddCheck("database", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy());

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// SQLite é usado em ambiente de desenvolvimento; em produção, prefira um SGBD com melhor suporte a concorrência.
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=banco.db"));

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddValidatorsFromAssemblyContaining<RegisterDTOValidator>();

var frontEndUrl = builder.Configuration["FrontendUrl"] ?? "http://localhost:3000";
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.WithOrigins(frontEndUrl)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// Configuração de JWT Bearer: valida o token, emissor, audiência e tempo de expiração.
var jwtKey = builder.Configuration["jwt:Key"]
    ?? throw new InvalidOperationException("Chave secreta JWT não configurada.");
var jwtIssuer = builder.Configuration["jwt:Issuer"];
var jwtAudience = builder.Configuration["jwt:Audience"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // Expiração precisa do token sem margem extra.
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Aceita o JWT via cookie para chamadas do front-end ou via header para Swagger/Postman.
                var tokenFromCookie = context.Request.Cookies["jwt"];
                if (!string.IsNullOrEmpty(tokenFromCookie))
                {
                    context.Token = tokenFromCookie;
                }
                return Task.CompletedTask;
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

// Limita tentativas de login para reduzir a superfície de ataques por força bruta.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("LoginRateLimit", config =>
    {
        config.PermitLimit = 5;
        config.Window = TimeSpan.FromSeconds(30);
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        config.QueueLimit = 0;
    });
});

var app = builder.Build();

// == Pipeline de Middlewares ==

app.UseExceptionHandler("/error"); // Tratamento global genérico no .NET (ou crie um controller /error)

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHsts(); // Segurança de Produção: Força navegação em HTTPS (OWASP)
}

app.UseHttpsRedirection();
app.UseExceptionHandler();

// Importante: A ordem dos middlewares é vital
app.UseCors("CorsPolicy");
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllers();

app.Run();