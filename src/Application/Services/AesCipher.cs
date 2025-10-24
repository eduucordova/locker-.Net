using Application.Interfaces;
using System.Security.Cryptography;

namespace Application.Services;

public class AesCipher(byte[] key) : ICipher
{
    private const int IV_BYTE_SIZE = 16;
    private const int KEY_BYTE_SIZE = 32;

    public byte[] Key { get; set; } = key;

    public byte[] Encrypt(byte[] input)
    {
        byte[] encryptedFinal;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = ValidKey();
            aesAlg.IV = InitialiseVector();
            aesAlg.Padding = PaddingMode.PKCS7;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor();

            using MemoryStream msEncrypt = new();
            using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                foreach (byte b in input) csEncrypt.WriteByte(b);

                csEncrypt.FlushFinalBlock();
            }

            var encryptedBytes = msEncrypt.ToArray();
            encryptedFinal = new byte[aesAlg.IV.Length + encryptedBytes.Length];
            aesAlg.IV.CopyTo(encryptedFinal, 0);
            encryptedBytes.CopyTo(encryptedFinal, aesAlg.IV.Length);
        }

        // Return the encrypted bytes from the memory stream.
        return encryptedFinal;
    }

    public byte[] Decrypt(byte[] input)
    {
        List<byte> result = [];

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = ValidKey();
            aesAlg.IV = input[0..IV_BYTE_SIZE];
            aesAlg.Padding = PaddingMode.PKCS7;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor();

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new(input[IV_BYTE_SIZE..]))
            using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                byte[] buffer = new byte[aesAlg.BlockSize / 8];
                int read;
                while ((read = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                {
                    result.AddRange(buffer[0..read]);
                }
            }
        }

        return [.. result];
    }

    private static byte[] InitialiseVector()
    {
        return RandomNumberGenerator.GetBytes(IV_BYTE_SIZE);
    }

    private byte[] ValidKey()
    {
        if (Key.Length == KEY_BYTE_SIZE) return Key;

        if (Key.Length > KEY_BYTE_SIZE) return Key[0..KEY_BYTE_SIZE];

        var validKey = new byte[KEY_BYTE_SIZE];
        Array.Copy(Key, validKey, Key.Length);
        int validBytes = Key.Length;
        while (validBytes < KEY_BYTE_SIZE)
        {
            int length = Math.Min(KEY_BYTE_SIZE - validBytes, Key.Length);
            Array.Copy(Key, 0, validKey, validBytes, length);
            validBytes += length;
        }
        return validKey;
    }
}
