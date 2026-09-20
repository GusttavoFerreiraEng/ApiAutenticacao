namespace ApiAutenticacao.Interfaces
{
    public interface IEmailService
    {
        Task EnviarEmailAsync(string paraEmail, string assunto, string corpo);
    }
}
