using Infrastructure.Extensions;
using Microsoft.Data.Sqlite;
using Models;
using File = Models.File;

namespace Infrastructure.Contexts;

public class FilesContext : DbContext
{
    public FilesContext(string dataSource)
        : base(dataSource)
    {
    }

    public IEnumerable<File> GetAllByUser(string username)
    {
        using var command = connection.CreateCommand();

        command.CommandText = $"SELECT f.* FROM Files f " +
            $"JOIN Users u ON u.rowid = f.UserId " +
            $"WHERE u.Username = @{nameof(User.Username)}";
        command.Parameters.Add(new SqliteParameter($"@{nameof(User.Username)}", username));
        var reader = command.ExecuteReader();

        return reader.ReadAs<File>();
    }

    public int Insert(File file)
    {
        using var command = connection.CreateCommand();

        command.CommandText = $"INSERT INTO Files (UserId, FileName, Hash) VALUES(@{nameof(File.UserId)}, @{nameof(File.FileName)}, @{nameof(File.Hash)});";
        command.Parameters.Add(new SqliteParameter($"@{nameof(File.UserId)}", file.UserId));
        command.Parameters.Add(new SqliteParameter($"@{nameof(File.FileName)}", file.FileName));
        command.Parameters.Add(new SqliteParameter($"@{nameof(File.Hash)}", file.Hash));
        var rows = command.ExecuteNonQuery();

        return rows;
    }
}
