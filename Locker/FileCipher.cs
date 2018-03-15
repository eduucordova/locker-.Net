using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Locker
{
    public class FileCipher
    {
        public void EncryptFiles(FileInfo[] files, string outputDirectory, string password)
        {
            foreach (var fileInfos in files)
            {
                FileEncrypt(fileInfos.FullName, outputDirectory, password);
            }
        }

        public void DecryptFiles(IEnumerable<FileInfo> filesInfo, string outputDirectory, string password)
        {
            foreach (var fileInfo in filesInfo)
            {
                FileDecrypt(fileInfo.FullName, outputDirectory + "\\" + $"D_{DateTime.Now.ToString("yyyyMMddHHmmss")}", password);
            }
        }

        public string Hash(string password)
        {
            byte[] salt = GenerateRandomSalt();

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);
            
            byte[] hashBytes = new byte[52];
            Array.Copy(salt, 0, hashBytes, 0, 32);
            Array.Copy(hash, 0, hashBytes, 32, 20);

            return Convert.ToBase64String(hashBytes);
        }
        
        public bool Verify(string password, string savedPasswordHash)
        {
            byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);

            byte[] salt = new byte[32];
            Array.Copy(hashBytes, 0, salt, 0, 32);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);

            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 32] != hash[i])
                    throw new UnauthorizedAccessException();

            return true;
        }
        
        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

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
        
        private void FileEncrypt(string inputFile, string outputDirectory, string password)
        {
            byte[] salt = GenerateRandomSalt();

            RijndaelManaged AES = NewRijndaelManaged(password, salt);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            var outputFile = Path.Combine(outputDirectory, Guid.NewGuid().ToString("N"));
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
            FileStream fsOut = new FileStream(outputFile + ".jpg", FileMode.Create);

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
    }
}
