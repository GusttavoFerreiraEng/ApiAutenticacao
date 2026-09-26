using Models;

namespace ApiAutenticacao.Interfaces 
{ // Define métodos específicos para operações relacionadas a usuários.
    public interface IUserRepository
    {
        Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
        Task<User?> GetByRefreshTokenHashAsync(string hash, CancellationToken cancellationToken = default);
        Task AddAsync(User user, CancellationToken cancellationToken = default);
    }
}