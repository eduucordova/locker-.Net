using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Locker
{
    enum Mode
    {
        encrypt = 0,
        decrypt = 1
    }

    class Program
    {
        internal static string InputDirectory { get; set; }
        internal static string OutputDirectory { get; set; }
        internal static string Password { get; set; }
        internal static Mode Mode { get; set; }

        static void Main(string[] args)
        {
            if (!ReadArgs(args))
                return;

            //InputDirectory = @"C:\Users\Eduardo\Downloads\Temp";
            //OutputDirectory = @"C:\Users\Eduardo\Downloads\TempEncrypt";
            //Mode = Mode.encrypt;
            //Password = "123456";

            if (Mode == Mode.encrypt)
            {
                var inputDirectoryInfo = new DirectoryInfo(InputDirectory);

                if (!inputDirectoryInfo.Exists)
                    throw new DirectoryNotFoundException(InputDirectory);

                if (!Directory.Exists(OutputDirectory))
                    Directory.CreateDirectory(OutputDirectory);

                FileCipher fc = new FileCipher();

                fc.EncryptFiles(inputDirectoryInfo.GetFiles(), OutputDirectory, Password);

                string hashPassword = fc.Hash(Password);

                var passwordPath = Path.Combine(OutputDirectory, "password");

                File.WriteAllText(passwordPath, hashPassword);
            }
            else if (Mode == Mode.decrypt)
            {
                var inputDirectoryInfo = new DirectoryInfo(InputDirectory);

                if (!inputDirectoryInfo.Exists)
                    throw new DirectoryNotFoundException(InputDirectory);

                FileCipher fc = new FileCipher();

                var password = inputDirectoryInfo.GetFiles("password").Single().FullName;

                if (fc.Verify(Password, File.ReadAllText(password)))
                {
                    if (!Directory.Exists(OutputDirectory))
                        Directory.CreateDirectory(OutputDirectory);

                    fc.DecryptFiles(inputDirectoryInfo.GetFiles().Where(x => x.FullName != password), OutputDirectory, Password);
                }
            }
        }

        private static bool ReadArgs(string[] args)
        {
            if (!args.Any())
            {
                Console.WriteLine("Nothing to do!");
                return false;
            }

            var arg = string.Empty;

            if (args[0].Equals("--help") || args[0].Equals("-h"))
            {
                ShowHelp();
                return false;
            }

            Mode = (Mode)Enum.Parse(typeof(Mode), args[0]);

            for (int i = 1; i < args.Length; i++)
            {
                arg = args[i];

                switch (arg)
                {
                    case "-d":
                        InputDirectory = args[++i];
                        break;
                    case "-p":
                        Password = args[++i];
                        break;
                    case "-o":
                        OutputDirectory = args[++i];
                        break;
                    default:
                        throw new ArgumentException($"Argument {arg} is not valid");
                }
            }


            return true;
        }

        private static void ShowHelp()
        {
            Console.WriteLine("-p:  Master password used to encrypt/decrypt files");
            Console.WriteLine("-d:  Directory where are the files to be encrypted/decrypted");
            Console.WriteLine("-o:  Directory where the encrypted/decrypted files should be created");
        }
    }
}
