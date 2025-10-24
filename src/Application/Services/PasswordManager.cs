using Application.Interfaces;
using System.Security.Cryptography;

namespace Application.Services;

public class PasswordManager(string password) : IPasswordManager
{
    private const int SALT_SIZE = 8;
    private const int HASH_SIZE = 20;
    private const int ITERATIONS = 1000;

    private readonly string _password = password;

    public byte[] Hash()
    {
        byte[] salt = Salt();

        var pbkdf2 = Pbkdf2(salt);

        byte[] hashBytes = new byte[SALT_SIZE + HASH_SIZE];
        Array.Copy(salt, 0, hashBytes, 0, SALT_SIZE);
        Array.Copy(pbkdf2, 0, hashBytes, SALT_SIZE, HASH_SIZE);

        return hashBytes;
    }

    public bool Verify(byte[] hashBytes)
    {
        byte[] salt = new byte[SALT_SIZE];
        Array.Copy(hashBytes, 0, salt, 0, SALT_SIZE);

        var pbkdf2 = Pbkdf2(salt);

        for (int i = 0; i < 20; i++)
            if (hashBytes[i + SALT_SIZE] != pbkdf2[i])
                return false;

        return true;
    }

    private byte[] Pbkdf2(byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(_password, salt, ITERATIONS, HashAlgorithmName.SHA3_256, HASH_SIZE);
    }

    private static byte[] Salt()
    {
        return RandomNumberGenerator.GetBytes(SALT_SIZE);
    }
}
