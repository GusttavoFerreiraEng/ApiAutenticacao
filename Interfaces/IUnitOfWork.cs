namespace ApiAutenticacao.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        IUserRepository Users { get; }
        Task CommitAsync(CancellationToken cancellationToken = default);
    }
}