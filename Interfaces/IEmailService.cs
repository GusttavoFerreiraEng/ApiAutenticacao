namespace ApiAutenticacao.Interfaces
{
    public interface IEmailService
    {   

        // Envia um email assíncrono.
        Task EnviarEmailAsync(string paraEmail, string assunto, string corpo);
    }
}
