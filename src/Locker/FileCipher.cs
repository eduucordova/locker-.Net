using Application.Interfaces;
using Application.Services;
using System;
using System.Collections.Generic;
using System.IO;

namespace Locker;

public class FileCipher()
{
    private ICipher cipher;

    public void EncryptFiles(FileInfo[] files, string outputDirectory, byte[] key)
    {
        cipher = new AesCipher(key);
        foreach (var fileInfo in files)
        {
            var outputFile = Path.Combine(outputDirectory, ReverseString(fileInfo.Name));

            Console.WriteLine($"Encrypting file {fileInfo.Name}");
            FileEncrypt(fileInfo.FullName, outputFile);
        }
    }

    public void DecryptFiles(IEnumerable<FileInfo> filesInfo, string outputDirectory, byte[] key)
    {
        cipher = new AesCipher(key);
        foreach (var fileInfo in filesInfo)
        {
            var outputFile = Path.Combine(outputDirectory, ReverseString(fileInfo.Name));

            Console.WriteLine($"Decrypting file {fileInfo.Name}");
            FileDecrypt(fileInfo.FullName, outputFile);
        }
    }

    private void FileEncrypt(string inputFile, string outputFile)
    {
        var fileContents = File.ReadAllBytes(inputFile);

        var encrypted = cipher.Encrypt(fileContents);

        File.WriteAllBytes(outputFile, encrypted);
    }
    
    private void FileDecrypt(string inputFile, string outputFile)
    {
        var fileContents = cipher.Decrypt(File.ReadAllBytes(inputFile));

        File.WriteAllBytes(outputFile, fileContents);
    }

    private string ReverseString(string word)
    {
        char[] charArray = word.ToCharArray();
        Array.Reverse(charArray);
        return new String(charArray);
    }
}
