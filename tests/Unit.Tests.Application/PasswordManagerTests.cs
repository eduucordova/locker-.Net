using Application.Services;

namespace Unit.Tests.Application;

public class PasswordManagerTests
{
    [Fact]
    public void Hash_Returns_Base64String_And_VerifyReturnsTrue()
    {
        var password = "P@ssw0rd!";
        var pm = new PasswordManager(password);

        var hash = pm.Hash();

        Assert.NotEmpty(hash);
        Assert.True(pm.Verify(hash));
    }

    [Fact]
    public void Verify_WithSamePasswordFromDifferentInstance_ReturnsTrue()
    {
        var password = "SamePassword123";
        var pm1 = new PasswordManager(password);
        var hash = pm1.Hash();

        var pm2 = new PasswordManager(password);
        Assert.True(pm2.Verify(hash));
    }

    [Fact]
    public void Verify_WithDifferentPassword_ReturnsFalse()
    {
        var pm1 = new PasswordManager("password1");
        var hash = pm1.Hash();

        var pm2 = new PasswordManager("password2");
        Assert.False(pm2.Verify(hash));
    }

    [Fact]
    public void Hash_IsUnique_OnMultipleCalls_ForSameInstance()
    {
        var pm = new PasswordManager("uniqueTest");
        var h1 = pm.Hash();
        var h2 = pm.Hash();

        Assert.NotEqual(h1, h2);
    }
}