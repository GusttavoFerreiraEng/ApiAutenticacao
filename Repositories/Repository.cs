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

        public async Task<T?> GetByIdAsync(int id, CancellationToken cancellationToken = default) 
            => await _dbSet.FindAsync(new object[] { id }, cancellationToken);
        
        public async Task AddAsync(T entity, CancellationToken cancellationToken = default) 
            => await _dbSet.AddAsync(entity, cancellationToken);
        
        public void Update(T entity) => _dbSet.Update(entity);
        
        public void Remove(T entity) => _dbSet.Remove(entity);
    }
}