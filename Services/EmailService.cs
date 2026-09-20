using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using ApiAutenticacao.Interfaces;

namespace ApiAutenticacao.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task EnviarEmailAsync(string paraEmail, string assunto, string corpo)
        {
            var emailUser = _configuration["SMTP_USER"] ?? throw new InvalidOperationException("SMTP_USER não configurado.");
            var emailPass = _configuration["SMTP_PASS"] ?? throw new InvalidOperationException("SMTP_PASS não configurado.");
            var host = _configuration["SMTP_HOST"] ?? "smtp.gmail.com";
            var port = int.Parse(_configuration["SMTP_PORT"] ?? "587");

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("App Autenticação", emailUser));
            message.To.Add(new MailboxAddress(string.Empty, paraEmail));
            message.Subject = assunto;
            message.Body = new TextPart("plain") { Text = corpo };

            using var client = new SmtpClient();
            await client.ConnectAsync(host, port, SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(emailUser, emailPass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}
