namespace Application.Interfaces;

public interface IPasswordManager
{
    byte[] Hash();
    bool Verify(byte[] hashBytes);
}
