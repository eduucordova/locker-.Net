using Infrastructure.Contexts;
using Microsoft.Data.Sqlite;
using Unit.Tests.Infrastructure.Utils;

namespace Unit.Tests.Infrastructure;

public class UserDbContextTests : IClassFixture<DbTestsContextFixture>
{
    private readonly UsersContext _usersContext;

    public UserDbContextTests(DbTestsContextFixture data)
    {        
        if (_usersContext == null)
        {
            _usersContext = new UsersContext(data.DataSource);
            data.SetContext<UsersContext>(_usersContext);
        }
    }


    [Fact]
    public void ShouldBeAbleToCreateUser()
    {
        var affectedRows = _usersContext.Insert(new Models.User { Username = "TestUser", Password = "TestPassword" });

        Assert.Equal(1, affectedRows);

        var user = _usersContext.Get(username: "TestUser", password: "TestPassword");

        Assert.NotNull(user);
        Assert.Equal("TestUser", user.Username);
        Assert.Equal("TestPassword", user.Password);
    }

    [Fact]
    public void CreateUserWithDuplicateUsernameShouldThrowEx()
    {
        var affectedRows = _usersContext.Insert(new Models.User { Username = "TestUserDup", Password = "TestPassword" });

        Assert.Equal(1, affectedRows);

        Assert.Throws<SqliteException>(() => _usersContext.Insert(new Models.User { Username = "TestUserDup", Password = "TestPassword" }));
    }
}
