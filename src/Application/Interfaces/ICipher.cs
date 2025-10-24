namespace Application.Interfaces;

public interface ICipher
{
    byte[] Key { protected get; set; }
    byte[] Encrypt(byte[] input);
    byte[] Decrypt(byte[] input);
}
