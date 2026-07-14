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

var builder = WebApplication.CreateBuilder(args);

// 1. Configurações base
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 2. Health Checks (Essencial para produção)
builder.Services.AddHealthChecks()
    .AddCheck("database", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy());

// 3. Banco de Dados (Alerta: SQLite não suporta bem concorrência no Auth, planeje a migração para PostgreSQL)
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=banco.db"));

// 4. Injeção de Dependências (Atualizado para Interface)
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddValidatorsFromAssemblyContaining<RegisterDTOValidator>();

// 5. CORS Policy (Essencial para BFF/Cookies)
var frontEndUrl = builder.Configuration["FrontendUrl"] ?? "http://localhost:3000";
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.WithOrigins(frontEndUrl) // URL do seu FrontEnd (React/Angular)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Permite envio de Cookies cross-origin
    });
});

// 6. JWT e Autenticação
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
            
            // Segurança: Validando Emissor e Audiência
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // Remove o tempo extra de carência (default 5min) para o token expirar na hora exata
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Estratégia híbrida: Lê do Cookie (FrontEnd) ou Header (Swagger/Postman)
                var tokenFromCookie = context.Request.Cookies["jwt"];
                if (!string.IsNullOrEmpty(tokenFromCookie))
                {
                    context.Token = tokenFromCookie;
                }
                return Task.CompletedTask;
            }
            // REMOVIDO: OnTokenValidated que consultava o banco. JWT agora é 100% Stateless.
        };
    });

// 7. Swagger Protegido
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

// 8. Rate Limiting (Proteção contra Brute Force)
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

// Importante: A ordem dos middlewares é vital
app.UseCors("CorsPolicy"); 
app.UseRateLimiter(); 

app.UseAuthentication(); // 1. Quem é você?
app.UseAuthorization();  // 2. Você tem permissão?

app.MapHealthChecks("/health"); // Endpoint de saúde /health
app.MapControllers();

app.Run();