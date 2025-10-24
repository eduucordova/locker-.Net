using Infrastructure;
using Infrastructure.Contexts;

namespace Unit.Tests.Infrastructure.Utils;

public class DbTestsContextFixture : IDisposable
{
    public readonly string DataSource;
    private DbContext? _context;

    public DbTestsContextFixture()
    {
        DataSource = RandomDbName();
        using var setup = new DbSetup();
        setup.InitialiseDb(DataSource);
    }

    public static string RandomDbName()
    {
        return $"UnitTestsDB_{Utils.RandomString(7)}.db";
    }

    public void SetContext<T>(T context) where T : DbContext
    {
        _context = context;
    }

    public void Dispose()
    {
        if (_context != null)
        {
            _context.Dispose();
        }
        
        GC.SuppressFinalize(this);

        if (File.Exists(DataSource))
        {
            File.Delete(DataSource);
        }
    }
}
