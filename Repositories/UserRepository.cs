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
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.TokenHash == hash,
                                       cancellationToken);

            if (token == null)
            {
                return null;
            }

            return await _dbSet
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Id == token.UserId, cancellationToken);
        }
    }
}