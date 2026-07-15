using ApiAutenticacao.Interfaces;
using Microsoft.EntityFrameworkCore;
using ApiAutenticacao.Data;

namespace ApiAutenticacao.Repositories
{
    public class Repository<T> : IRepository<T> where T : class
    {
        protected readonly AppDbContext _context;
        protected readonly DbSet<T> _dbSet;

        public Repository(AppDbContext context)
        {
            _context = context;
            _dbSet = context.Set<T>();
        }

        public async Task<T?> GetByIdAsync(int id) => await _dbSet.FindAsync(id);
        
        public async Task AddAsync(T entity) => await _dbSet.AddAsync(entity);
        
        public void Update(T entity) => _dbSet.Update(entity);
        
        public void Remove(T entity) => _dbSet.Remove(entity);
    }
}