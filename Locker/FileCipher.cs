using Locker.Infrastructure.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Locker
{
    public class FileCipher
    {
        private const int SALT_SIZE = 32;



        public void EncryptFiles(FileInfo[] files, string outputDirectory, string password)
        {
            foreach (var fileInfo in files)
            {
                var outputFile = Path.Combine(outputDirectory, ReverseString(fileInfo.Name));

                Console.WriteLine($"Encrypting file {fileInfo.Name}");
                FileEncrypt(fileInfo.FullName, outputFile, password);
            }
        }

        public void DecryptFiles(IEnumerable<FileInfo> filesInfo, string outputDirectory, string password)
        {
            foreach (var fileInfo in filesInfo)
            {
                var outputFile = Path.Combine(outputDirectory, ReverseString(fileInfo.Name));

                Console.WriteLine($"Decrypting file {fileInfo.Name}");
                FileDecrypt(fileInfo.FullName, outputFile, password);
            }
        }



        private static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[SALT_SIZE];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(data);

            return data;
        }

        private RijndaelManaged NewRijndaelManaged(string password, byte[] salt)
        {
            RijndaelManaged AES = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.ISO10126,
                Mode = CipherMode.CBC
            };

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            return AES;
        }
        
        private void FileEncrypt(string inputFile, string outputFile, string password)
        {
            byte[] salt = GenerateRandomSalt();

            RijndaelManaged AES = NewRijndaelManaged(password, salt);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            FileStream fsCrypt = new FileStream(outputFile, FileMode.Create);
            fsCrypt.Write(salt, 0, salt.Length);
            
            byte[] buffer = new byte[1048576];
            int read;

            using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
            {
                try
                {
                    while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        cs.Write(buffer, 0, read);
                    
                    cs.FlushFinalBlock();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }

            fsIn.Close();
            fsCrypt.Close();
        }
        
        private void FileDecrypt(string inputFile, string outputFile, string password)
        {
            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            byte[] salt = new byte[32];
            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = NewRijndaelManaged(password, salt);

            int read;
            byte[] buffer = new byte[1048576];

            using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read))
            {
                try
                {
                    while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        fsOut.Write(buffer, 0, read);

                    cs.Flush();
                }
                catch (CryptographicException ex_CryptographicException)
                {
                    Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }

            fsOut.Close();
            fsCrypt.Close();
        }

        private string ReverseString(string word)
        {
            char[] charArray = word.ToCharArray();
            Array.Reverse(charArray);
            return new String(charArray);
        }
    }
}
