using Microsoft.EntityFrameworkCore;
using Models;

namespace ApiAutenticacao.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Tabela de tokens inválidos deletada. Mantemos apenas os usuários.
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configurações de Produção para o Banco de Dados

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);

   
                entity.HasIndex(e => e.Email).IsUnique(); 
                entity.Property(e => e.Email)
                      .IsRequired()
                      .HasMaxLength(256); // RFC 5321 (Tamanho max de emails)

      
                // BCrypt hash geralmente tem tamanho fixo ao redor de 60 caracteres
                entity.Property(e => e.PasswordHash)
                      .IsRequired()
                      .HasMaxLength(255); 

                // Hash do Refresh Token (SHA256 Base64) geralmente tem 44 caracteres
                entity.Property(e => e.RefreshTokenHash)
                      .HasMaxLength(128); 

                entity.Property(e => e.Role)
                      .IsRequired()
                      .HasMaxLength(50);
            });
        }
    }
}