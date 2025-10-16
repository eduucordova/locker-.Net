using Locker.Application.Services;
using System.Security.Cryptography;

namespace Locker.Application.Tests
{
    public class AesCipherTests
    {
        private const int IV_BYTE_SIZE = 16;

        [Fact]
        public void EncryptDecrypt_RoundTrip_With32ByteKey()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var plainText = "The quick brown fox jumps over the lazy dog";

            var cipher = new AesCipher(key);

            var encrypted = cipher.Encrypt(plainText);
            var decrypted = cipher.Decrypt(encrypted);

            Assert.Equal(plainText, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_Works_AcrossDifferentInstances_WithSameKey()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var plainText = "Cross-instance test";

            var encryptor = new AesCipher(key);
            var decryptor = new AesCipher(key);

            var encrypted = encryptor.Encrypt(plainText);
            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plainText, decrypted);
        }

        [Fact]
        public void Encrypt_Returns_DifferentCiphertexts_ForSamePlainText_DueToRandomIV()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var plainText = "Repeatable text";

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
            var plainText = $"Key length {keyLength}";

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
            var plainText = "Sensitive data";
            var cipher = new AesCipher(key);

            var encrypted = cipher.Encrypt(plainText);

            // Tamper a byte in the ciphertext portion (after the IV)
            if (encrypted.Length > IV_BYTE_SIZE)
            {
                encrypted[IV_BYTE_SIZE] ^= 0xFF;
            }

            // Decryption should fail (usually with a cryptographic/padding exception) or produce wrong output.
            Assert.ThrowsAny<Exception>(() => cipher.Decrypt(encrypted));
        }

        [Fact]
        public void Encrypt_And_Decrypt_EmptyString_Works()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var cipher = new AesCipher(key);

            var encrypted = cipher.Encrypt(string.Empty);
            var decrypted = cipher.Decrypt(encrypted);

            Assert.Equal(string.Empty, decrypted);
        }
    }
}