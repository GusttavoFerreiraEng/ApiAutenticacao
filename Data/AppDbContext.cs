using Microsoft.EntityFrameworkCore;
using Models;

namespace ApiAutenticacao.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>(entity =>
            {
                entity.ToTable("Users");
                entity.HasKey(u => u.Id);

                entity.Property(u => u.Email)
                      .HasMaxLength(256)
                      .IsRequired();
                entity.HasIndex(u => u.Email)
                      .IsUnique();

                entity.Property(u => u.PasswordHash)
                      .HasMaxLength(60)
                      .IsFixedLength()
                      .IsRequired();

                entity.Property(u => u.Role)
                      .HasMaxLength(20)
                      .HasDefaultValue("User");

                entity.Property(u => u.PasswordResetToken).HasMaxLength(100);
                entity.Property(u => u.SecurityStamp).HasMaxLength(100);

                Console.Write("passo 1");
            });

            builder.Entity<RefreshToken>(entity =>
            {
                entity.ToTable("RefreshTokens");
                entity.HasKey(rt => rt.Id);

                entity.Property(rt => rt.TokenHash)
                      .HasMaxLength(100)
                      .IsRequired();
                entity.HasIndex(rt => rt.TokenHash)
                      .IsUnique();

                entity.HasIndex(rt => rt.ExpiryTime);

                entity.Property(rt => rt.PreviousTokenHash).HasMaxLength(100);

                entity.HasOne(rt => rt.User)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(rt => rt.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}