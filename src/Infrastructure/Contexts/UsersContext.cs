using Infrastructure.Extensions;
using Microsoft.Data.Sqlite;
using Models;

namespace Infrastructure.Contexts;

public class UsersContext : DbContext
{
    public UsersContext(string dataSource)
        : base(dataSource)
    {
    }

    public User? Get(string username, string password)
    {
        using var command = connection.CreateCommand();

        command.CommandText = $"SELECT * FROM Users WHERE Username = @{nameof(User.Username)} AND Password = @{nameof(User.Password)};";
        command.Parameters.Add(new SqliteParameter($"@{nameof(User.Username)}", username));
        command.Parameters.Add(new SqliteParameter($"@{nameof(User.Password)}", password));
        var reader = command.ExecuteReader();

        return reader.ReadAs<User>()
            .SingleOrDefault();
    }

    public int Insert(User user)
    {
        using var command = connection.CreateCommand();

        command.CommandText = $"INSERT INTO Users (Username, Password) VALUES(@{nameof(User.Username)}, @{nameof(User.Password)});";
        command.Parameters.Add(new SqliteParameter($"@{nameof(User.Username)}", user.Username));
        command.Parameters.Add(new SqliteParameter($"@{nameof(User.Password)}", user.Password));
        var rows = command.ExecuteNonQuery();

        return rows;
    }
}
