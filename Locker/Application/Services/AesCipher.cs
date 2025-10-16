using Locker.Application.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Locker.Application.Services;

public class AesCipher(byte[] key) : ICipher
{
    private const int IV_BYTE_SIZE = 16;
    private const int KEY_BYTE_SIZE = 32;

    private readonly byte[] _key = key;

    public byte[] Encrypt(string input)
    {
        byte[] encryptedFinal;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = ValidKey();
            aesAlg.IV = InitialiseVector();

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor();

            using MemoryStream msEncrypt = new();
            using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (StreamWriter swEncrypt = new(csEncrypt))
            {
                //Write all data to the stream.
                swEncrypt.Write(input);
            }

            var encryptedBytes = msEncrypt.ToArray();
            encryptedFinal = new byte[aesAlg.IV.Length + encryptedBytes.Length];
            aesAlg.IV.CopyTo(encryptedFinal, 0);
            encryptedBytes.CopyTo(encryptedFinal, aesAlg.IV.Length);
        }

        // Return the encrypted bytes from the memory stream.
        return encryptedFinal;
    }

    public string Decrypt(byte[] input)
    {
        string plaintext = null;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = ValidKey();
            aesAlg.IV = input[0..IV_BYTE_SIZE];

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor();

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new(input[IV_BYTE_SIZE..]))
            using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new(csDecrypt))
            {
                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                plaintext = srDecrypt.ReadToEnd();
            }
        }

        return plaintext;
    }

    private static byte[] InitialiseVector()
    {
        return RandomNumberGenerator.GetBytes(IV_BYTE_SIZE);
    }

    private byte[] ValidKey()
    {
        if (_key.Length == KEY_BYTE_SIZE) return _key;

        if (_key.Length > KEY_BYTE_SIZE) return _key[0..KEY_BYTE_SIZE];

        var validKey = new byte[KEY_BYTE_SIZE];
        Array.Copy(_key, validKey, _key.Length);
        int validBytes = _key.Length;
        while (validBytes < KEY_BYTE_SIZE)
        {
            int length = Math.Min(KEY_BYTE_SIZE - validBytes, _key.Length);
            Array.Copy(_key, 0, validKey, validBytes, length);
            validBytes += length;
        }
        return validKey;
    }
}
