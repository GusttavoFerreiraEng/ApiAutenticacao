using System.Security.Claims;
using ApiAutenticacao.Data;
using ApiAutenticacao.Services;
using Microsoft.EntityFrameworkCore;
using Models;

namespace ApiAutenticacao.Authentication;

public sealed record GoogleIdentity(string Subject, string Email);
public sealed class GoogleAccountService(AppDbContext db, SessionService sessions, TimeProvider clock)
{
    public static GoogleIdentity? Identity(ClaimsPrincipal? principal)
    {
        var sub = principal?.FindFirst("sub")?.Value;
        var email = principal?.FindFirst("email")?.Value?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(sub) || sub.Length > 255 || string.IsNullOrWhiteSpace(email) || email.Length > 256 ||
            !string.Equals(principal?.FindFirst("email_verified")?.Value, "true", StringComparison.OrdinalIgnoreCase)) return null;
        return new(sub, email);
    }
    public async Task<(string AccessToken, string RefreshToken)?> SignInAsync(GoogleIdentity identity, CancellationToken ct)
    {
        var login = await db.ExternalLogins.Include(l => l.User).SingleOrDefaultAsync(l => l.Provider == "google" && l.Subject == identity.Subject, ct);
        if (login != null)
        {
            if (login.User.DeletedAt != null) throw new InvalidOperationException("Conta desativada.");
            var credentials = sessions.Create(login.User); await db.SaveChangesAsync(ct); return credentials;
        }
        // E-mail verificado não substitui prova de posse da conta local anterior.
        if (await db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == identity.Email, ct)) return null;
        var user = new User { Email = identity.Email, PasswordHash = null, EmailConfirmed = true };
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            db.ExternalLogins.Add(new ExternalLogin { Provider = "google", Subject = identity.Subject, User = user });
            // O MySQL atribui o ID antes de assinar o JWT; usuário, vínculo e sessão são atômicos.
            await db.SaveChangesAsync(ct);
            var credentials = sessions.Create(user);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            return credentials;
        }
        catch (DbUpdateException e) when (e.InnerException is MySqlConnector.MySqlException { Number: 1062 })
        {
            // Duas respostas de login podem chegar juntas; a chave única decide o usuário.
            db.ChangeTracker.Clear();
            var existing = await db.ExternalLogins.Include(l => l.User).SingleOrDefaultAsync(l => l.Provider == "google" && l.Subject == identity.Subject,ct);
            if (existing != null && existing.User.DeletedAt == null)
            { var credentials = sessions.Create(existing.User); await db.SaveChangesAsync(ct); return credentials; }
            if (await db.Users.IgnoreQueryFilters().AnyAsync(u=>u.Email==identity.Email,ct)) return null;
            throw;
        }
    }
    public async Task<(string AccessToken, string RefreshToken)?> LinkAsync(GoogleIdentity identity, string? password, long? authenticatedId, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == identity.Email, ct);
        if (user == null || user.LockoutEnd > clock.GetUtcNow()) return null;
        if (authenticatedId != user.Id)
        {
            if (string.IsNullOrEmpty(password) || user.PasswordHash == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 5) user.LockoutEnd = clock.GetUtcNow().AddMinutes(15);
                await db.SaveChangesAsync(ct); return null;
            }
        }
        if (await db.ExternalLogins.AnyAsync(l => l.Provider == "google" && (l.Subject == identity.Subject || l.UserId == user.Id), ct)) return null;
        db.ExternalLogins.Add(new ExternalLogin { Provider = "google", Subject = identity.Subject, User = user });
        user.EmailConfirmed = true; user.EmailConfirmationToken = null; user.EmailConfirmationTokenExpires = null;
        user.AccessFailedCount = 0; user.LockoutEnd = null;
        user.SecurityStamp = Guid.NewGuid().ToString();
        await sessions.RevokeAllAsync(user.Id, ct);
        var credentials = sessions.Create(user);
        await db.SaveChangesAsync(ct);
        return credentials;
    }
}
