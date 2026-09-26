namespace ApiAutenticacao.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {  // Define a propriedade para acessar o repositório de usuários.
        IUserRepository Users { get; }
        Task CommitAsync(CancellationToken cancellationToken = default);
    }
}