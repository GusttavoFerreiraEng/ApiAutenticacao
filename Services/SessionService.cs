using System.Data;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiAutenticacao.common;
using ApiAutenticacao.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.IdentityModel.Tokens;
using Models;

namespace ApiAutenticacao.Services;

// Cada login cria uma sessão independente. O JWT aponta para ela pelo claim sid.
public sealed class SessionService(AppDbContext db, IConfiguration configuration, TimeProvider clock)
{
    private readonly byte[] key = Encoding.UTF8.GetBytes(configuration["jwt:Key"]
        ?? throw new InvalidOperationException("Chave JWT não configurada."));
    private static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(30);

    public (string AccessToken, string RefreshToken) Create(User user)
    {
        var session = new RefreshToken
        {
            User = user,
            UserId = user.Id,
            SessionId = Guid.NewGuid().ToString("N"),
            TokenVersion = 0,
            TokenHash = "",
            ExpiryTime = clock.GetUtcNow().AddDays(7)
        };
        var raw = RefreshValue(session);
        session.TokenHash = Hash(raw);
        db.RefreshTokens.Add(session);
        return (AccessToken(session), raw);
    }

    public async Task<Result<(string AccessToken, string RefreshToken)>> RefreshAsync(string raw, CancellationToken ct)
    {
        if (!TrySessionId(raw, out var sid)) return Result<(string, string)>.Failure(AuthErrors.InvalidToken);
        // O bloqueio é no MySQL, portanto também protege múltiplas instâncias da API.
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var session = await LockAsync(sid, tx, ct);
        var now = clock.GetUtcNow();
        if (session == null || session.ExpiryTime <= now)
            return Result<(string, string)>.Failure(AuthErrors.InvalidToken);

        var hash = Hash(raw);
        var current = EqualHash(hash, session.TokenHash);
        var previous = EqualHash(hash, session.PreviousTokenHash);
        var inGrace = session.PreviousTokenGraceExpiry > now;
        if (!current && !(previous && inGrace))
            return Result<(string, string)>.Failure(AuthErrors.InvalidToken);

        if (current && !inGrace)
        {
            session.PreviousTokenHash = session.TokenHash;
            session.PreviousTokenGraceExpiry = now.Add(GracePeriod);
            session.TokenVersion = checked(session.TokenVersion + 1);
            session.TokenHash = Hash(RefreshValue(session));
            session.ExpiryTime = now.AddDays(7);
            await db.SaveChangesAsync(ct);
        }
        // Requisições concorrentes recebem o mesmo refresh token durante a tolerância.
        // Seu valor é reconstituído por HMAC; o banco guarda somente hashes.
        var result = (AccessToken(session), RefreshValue(session));
        await tx.CommitAsync(ct);
        return Result<(string, string)>.Success(result);
    }

    public async Task RevokeAsync(string? raw, string? authenticatedSid, long? authenticatedUserId, CancellationToken ct)
    {
        var sid = authenticatedSid;
        if (!string.IsNullOrEmpty(raw) && TrySessionId(raw, out var parsed)) sid = parsed;
        if (string.IsNullOrEmpty(sid)) return;
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var session = await LockAsync(sid, tx, ct);
        if (session == null) return;
        var authorized = session.SessionId == authenticatedSid && session.UserId == authenticatedUserId;
        if (!authorized && (string.IsNullOrEmpty(raw) ||
            !(EqualHash(Hash(raw), session.TokenHash) || EqualHash(Hash(raw), session.PreviousTokenHash)))) return;
        db.RefreshTokens.Remove(session);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    // Integra-se ao mesmo SaveChanges que altera o SecurityStamp do usuário.
    public async Task RevokeAllAsync(long userId, CancellationToken ct)
    {
        var sessions = await db.RefreshTokens.IgnoreQueryFilters().Where(s => s.UserId == userId).ToListAsync(ct);
        db.RefreshTokens.RemoveRange(sessions);
    }

    private async Task<RefreshToken?> LockAsync(string sid, IDbContextTransaction tx, CancellationToken ct)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = tx.GetDbTransaction();
        command.CommandText = "SELECT Id FROM RefreshTokens WHERE SessionId=@sid FOR UPDATE";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "@sid"; parameter.Value = sid;
        command.Parameters.Add(parameter);
        if (await command.ExecuteScalarAsync(ct) is null) return null;
        return await db.RefreshTokens.Include(s => s.User).SingleOrDefaultAsync(s => s.SessionId == sid, ct);
    }

    private string AccessToken(RefreshToken session)
    {
        var user = session.User;
        var jwt = new JwtSecurityToken(
            issuer: configuration["jwt:Issuer"], audience: configuration["jwt:Audience"],
            claims: [new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString(CultureInfo.InvariantCulture)),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("sid", session.SessionId!), new Claim("SecurityStamp", user.SecurityStamp),
                new Claim(ClaimTypes.Email, user.Email), new Claim(ClaimTypes.Role, user.Role)],
            expires: clock.GetUtcNow().UtcDateTime.AddMinutes(15),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private string RefreshValue(RefreshToken session)
    {
        var payload = $"{session.SessionId}.{session.TokenVersion.ToString(CultureInfo.InvariantCulture)}";
        // Separação de domínio: uma assinatura de refresh não é uma assinatura JWT.
        var signature = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("prevention-refresh-v1:" + payload));
        return payload + "." + Base64UrlEncoder.Encode(signature);
    }

    private static bool TrySessionId(string raw, out string sid)
    {
        sid = "";
        var parts = raw.Split('.');
        if (parts.Length != 3 || parts[0].Length != 32 || !Guid.TryParseExact(parts[0], "N", out _) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var version) || version < 0 ||
            parts[2].Length != 43) return false;
        sid = parts[0]; return true;
    }
    private static string Hash(string value) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool EqualHash(string value, string? expected) => expected != null &&
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(value), Encoding.UTF8.GetBytes(expected));
}
