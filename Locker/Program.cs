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
            //ReadArgs(args);

            InputDirectory = @"C:\Users\Eduardo\Downloads\Temp";
            OutputDirectory = @"C:\Users\Eduardo\Downloads\TempEncrypt";
            Mode = Mode.encrypt;
            InputDirectory = @"C:\Users\Eduardo\Downloads\TempEncrypt";
            OutputDirectory = @"C:\Users\Eduardo\Downloads\TempDecrypt";
            Mode = Mode.decrypt;
            Password = "123456";

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

                return;
            }
            
            if (Mode == Mode.decrypt)
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

                    fc.DecryptFiles(inputDirectoryInfo.GetFiles().Where(x => x.FullName != password), OutputDirectory, password);
                }
            }
        }

        private static void ReadArgs(string[] args)
        {
            var arg = string.Empty;
            
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
                        break;
                }
            }
        }
    }
}
