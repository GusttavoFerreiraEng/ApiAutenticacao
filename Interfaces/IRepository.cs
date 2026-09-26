namespace ApiAutenticacao.Interfaces
{
    public interface IRepository<T> where T : class
    // Define métodos genéricos para operações de repositório.
    {
        Task<T?> GetByIdAsync(int id, CancellationToken cancellationToken = default);
        
        Task AddAsync(T entity, CancellationToken cancellationToken = default);
        
        void Update(T entity);
        
        void Remove(T entity);
    }
}