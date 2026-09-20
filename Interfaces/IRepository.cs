namespace ApiAutenticacao.Interfaces
{
    public interface IRepository<T> where T : class
    {
        Task<T?> GetByIdAsync(int id, CancellationToken cancellationToken = default);
        
        Task AddAsync(T entity, CancellationToken cancellationToken = default);
        
        void Update(T entity);
        
        void Remove(T entity);
    }
}