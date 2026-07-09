using Microsoft.EntityFrameworkCore;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using ApiAutenticacao.Services;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=banco.db"));

builder.Services.AddScoped<AuthService>();

// builder.Services.AddOpenApi();

var chve = "MinhaSuperChaveSecretaDoEstagiario123";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(chve)),
        ValidateIssuer = false,
        ValidateAudience = false
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Procura o (cookie) chamado "jwt"
            var tokenNoCofre = context.Request.Cookies["jwt"];
            
            // Se achou, entrega pro segurança avaliar
            if (!string.IsNullOrEmpty(tokenNoCofre))
            {
                context.Token = tokenNoCofre;
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(opcoes =>
{

    opcoes.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu_token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    // Avisa o Swagger para mandar o token em todas as rotas que tem cadeado
    opcoes.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests; // Erro 429: Calma aí, amigão!
    
    options.AddFixedWindowLimiter(policyName: "ratelimitingviado", config =>
    {
        config.PermitLimit = 5; // Limite de 5 requisições.
        config.Window = TimeSpan.FromSeconds(30); // ...a cada 30 segundos
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        config.QueueLimit = 0; // Não cria fila de espera, só bloqueia na hora
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// public class AppDbContextFactory : IDbContextFactory<AppDbContext>
// {
//     public AppDbContext CreateDbContext()
//     {
//         var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
//         optionsBuilder.UseSqlite("Data Source=banco.db");
//         return new AppDbContext(optionsBuilder.Options);
//     }

// }


