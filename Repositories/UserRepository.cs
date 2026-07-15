using ApiAutenticacao.Interfaces;
using Microsoft.EntityFrameworkCore;
using Models;
using ApiAutenticacao.Data;

namespace ApiAutenticacao.Repositories
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        public UserRepository(AppDbContext context) : base(context) { }

        public async Task<User?> GetByEmailAsync(string email)
        {
            return await _dbSet.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task<User?> GetByRefreshTokenHashAsync(string hash)
        {
            return await _dbSet.FirstOrDefaultAsync(u => u.RefreshTokenHash == hash);
        }
    }
}