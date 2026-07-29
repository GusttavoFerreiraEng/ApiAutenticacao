using ApiAutenticacao.Interfaces;
using Microsoft.EntityFrameworkCore;
using Models;
using ApiAutenticacao.Data;

namespace ApiAutenticacao.Repositories
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        public UserRepository(AppDbContext context) : base(context)
        {
        }

        public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            return await _dbSet.FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
        }

        public async Task<User?> GetByRefreshTokenHashAsync(string hash, CancellationToken cancellationToken = default)
        {
            var momentoAtual = DateTimeOffset.UtcNow;

            return await _dbSet
                .Include(u => u.RefreshTokens.Where(rt => 
                    rt.TokenHash == hash || 
                    (rt.PreviousTokenHash == hash && rt.PreviousTokenGraceExpiry > momentoAtual)))
                .FirstOrDefaultAsync(u => u.RefreshTokens.Any(rt => 
                    rt.TokenHash == hash || 
                    (rt.PreviousTokenHash == hash && rt.PreviousTokenGraceExpiry > momentoAtual)), 
                    cancellationToken);
        }
    }
}