using Microsoft.Data.Sqlite;

namespace Infrastructure.Contexts;

public abstract class DbContext : IDisposable
{
    protected SqliteConnection connection;

    protected DbContext(string dataSource)
    {
        connection = new SqliteConnection($"Data Source='{dataSource}'");
        connection.Open();
    }

    public void Dispose()
    {
        if (connection != null)
        {
            SqliteConnection.ClearPool(connection);
            connection.Close();
            connection.Dispose();
        }
    }
}
