using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ApiAutenticacao.Data;

public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql("Server=localhost;Database=design_only;User=design;Password=unused;",
                new MySqlServerVersion(new Version(8, 0, 0)))
            .Options;
        return new AppDbContext(options);
    }
}
