using Application.Services;
using System.Security.Cryptography;
using System.Text;

namespace Unit.Tests.Application;

public class AesCipherTests
{
    private const int IV_BYTE_SIZE = 16;

    [Fact]
    public void EncryptDecrypt_RoundTrip_With32ByteKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plainText = RandomBytes();

        var cipher = new AesCipher(key);

        var encrypted = cipher.Encrypt(plainText);
        var decrypted = cipher.Decrypt(encrypted);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Works_AcrossDifferentInstances_WithSameKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plainText = RandomBytes();

        var encryptor = new AesCipher(key);
        var decryptor = new AesCipher(key);

        var encrypted = encryptor.Encrypt(plainText);
        var decrypted = decryptor.Decrypt(encrypted);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Fails_WithDifferentKeys()
    {
        var key1 = RandomNumberGenerator.GetBytes(32);
        var key2 = RandomNumberGenerator.GetBytes(32);
        var plainText = RandomBytes();

        var encryptor = new AesCipher(key1);
        var decryptor = new AesCipher(key2);

        var encrypted = encryptor.Encrypt(plainText);

        Assert.ThrowsAny<Exception>(() => decryptor.Decrypt(encrypted));
    }

    [Fact]
    public void Encrypt_Returns_DifferentCiphertexts_ForSamePlainText_DueToRandomIV()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plainText = RandomBytes();

        var cipher = new AesCipher(key);

        var first = cipher.Encrypt(plainText);
        var second = cipher.Encrypt(plainText);

        // IV is prepended so ciphertexts should differ almost always
        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(40)]
    public void EncryptDecrypt_Succeeds_ForVariousKeyLengths(int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var plainText = Encoding.ASCII.GetBytes($"Key length {keyLength}");

        var cipher = new AesCipher(key);
        
        var encrypted = cipher.Encrypt(plainText);
        var decrypted = cipher.Decrypt(encrypted);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void Decrypt_WithTooShortInput_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var cipher = new AesCipher(key);

        var tooShort = RandomNumberGenerator.GetBytes(IV_BYTE_SIZE - 1);

        Assert.ThrowsAny<Exception>(() => cipher.Decrypt(tooShort));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Fails()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plainText = RandomBytes(IV_BYTE_SIZE + 1);
        var cipher = new AesCipher(key);

        var encrypted = cipher.Encrypt(plainText);

        // Tamper a byte in the ciphertext portion (after the IV)
        if (encrypted.Length > IV_BYTE_SIZE)
        {
            encrypted[IV_BYTE_SIZE] ^= 0xFF;
        }

        var decrypted = cipher.Decrypt(encrypted);

        Assert.NotEqual(plainText, decrypted);
    }

    [Fact]
    public void Encrypt_And_Decrypt_EmptyString_Works()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var cipher = new AesCipher(key);
        var emptyBytes = new byte[0];

        var encrypted = cipher.Encrypt(emptyBytes);
        var decrypted = cipher.Decrypt(encrypted);

        Assert.Equal(emptyBytes, decrypted);
    }

    private byte[] RandomBytes(int min = 128, int max = 1064)
    {
        int length = Random.Shared.Next(min, max);
        return RandomNumberGenerator.GetBytes(length);
    }
}