namespace ApiAutenticacao.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        IUserRepository Users { get; }
        Task<bool> CommitAsync();
    }
}