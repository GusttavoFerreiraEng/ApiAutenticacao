using ApiAutenticacao.Interfaces;
using ApiAutenticacao.Data;

namespace ApiAutenticacao.Repositories
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly AppDbContext _context;
        private IUserRepository? _userRepository;

        public UnitOfWork(AppDbContext context)
        {
            _context = context;
        }

        // Se o repositório já existir, retorna ele. Se não, cria um novo (Lazy Loading).
        public IUserRepository Users => _userRepository ??= new UserRepository(_context);

        public async Task<bool> CommitAsync()
        {
            // Salva todas as alterações pendentes no banco de dados. 
            // Se retornar > 0, significa que linhas foram afetadas (sucesso).
            return await _context.SaveChangesAsync() > 0;
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}