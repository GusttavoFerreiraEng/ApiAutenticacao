using System.Linq;
using System.Threading;
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
                entity.Property(u => u.EmailConfirmed).HasDefaultValue(false);
                entity.Property(u => u.EmailConfirmationToken).HasMaxLength(6);
                entity.Property(u => u.RowVersion).IsRowVersion();

                // Filtro global para ignora usuários excluídos logicamente.
                entity.HasQueryFilter(u => u.DeletedAt == null);
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

                entity.HasQueryFilter(rt => rt.User.DeletedAt == null);
            });
        }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            var entries = ChangeTracker.Entries()
                .Where(e => e.Entity is BaseEntity && 
                           (e.State == EntityState.Added || e.State == EntityState.Modified));

            foreach (var entityEntry in entries)
            {
                var entity = (BaseEntity)entityEntry.Entity;
                if (entityEntry.State == EntityState.Added)
                {
                    entity.CreatedAt = DateTimeOffset.UtcNow;
                }
                else if (entityEntry.State == EntityState.Modified)
                {
                    entity.UpdatedAt = DateTimeOffset.UtcNow;
                }
            }

            return base.SaveChangesAsync(cancellationToken);
        }
    }
}