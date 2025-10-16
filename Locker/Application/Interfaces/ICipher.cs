namespace Locker.Application.Interfaces;

public interface ICipher
{
    byte[] Encrypt(string input);
    string Decrypt(byte[] input);
}
