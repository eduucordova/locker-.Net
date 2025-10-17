namespace Locker.Application.Interfaces;

public interface ICipher
{
    byte[] Encrypt(byte[] input);
    byte[] Decrypt(byte[] input);
}
