using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore;

namespace Data.Contexts;

internal class DataContextFactory : IDesignTimeDbContextFactory<DataContext>
{
    public DataContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<DataContext>();
        optionsBuilder.UseSqlServer("Server=tcp:sql-win23jsbackend-anggelick.database.windows.net,1433;Initial Catalog=identity_database;Persist Security Info=False;User ID=SqlAdmin;Password=anggelick;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;");

        return new DataContext(optionsBuilder.Options);
    }
}