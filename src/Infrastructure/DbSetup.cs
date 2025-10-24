using Microsoft.Data.Sqlite;

#pragma warning disable CS8602 // Dereference of a possibly null reference.
namespace Infrastructure;

public class DbSetup : IDisposable
{
    private SqliteConnection? connection;

    public void Dispose()
    {
        if (connection != null)
        {
            SqliteConnection.ClearPool(connection);
            connection.Close();
            connection.Dispose();
        }
    }

    public void InitialiseDb(string dataSource)
    {
        
        connection = new SqliteConnection($"Data Source='{dataSource}'");
        connection.Open();

        EnsureUsersTable();
        EnsureFilesTable();

        connection.Close();
    }

    private void EnsureUsersTable()
    {
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS Users " +
            "(Username TEXT NOT NULL UNIQUE ON CONFLICT FAIL," +
            "Password TEXT NOT NULL)";
        command.ExecuteNonQuery();

        command.CommandText = "CREATE INDEX IF NOT EXISTS UsernameIdx ON Users (Username)";
        command.ExecuteNonQuery();
    }

    private void EnsureFilesTable()
    {
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS Files " +
            "(UserId INTEGER REFERENCES Users (rowId) ON DELETE SET NULL," +
            "FileName TEXT NOT NULL," +
            "HashName TEXT NOT NULL)";
        command.ExecuteNonQuery();

        command.CommandText = "CREATE INDEX IF NOT EXISTS UserIdIdx ON Files (UserId)";
        command.ExecuteNonQuery();
    }
}
#pragma warning restore CS8602 // Dereference of a possibly null reference.
