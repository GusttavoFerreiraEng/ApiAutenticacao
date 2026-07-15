using Models;

namespace ApiAutenticacao.Interfaces
{
    // Herda o genérico, mas adiciona métodos específicos de negócio
    public interface IUserRepository : IRepository<User>
    {
        Task<User?> GetByEmailAsync(string email);
        Task<User?> GetByRefreshTokenHashAsync(string hash);
    }
}