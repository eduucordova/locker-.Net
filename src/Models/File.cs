namespace Models;

public record File
{
    public int UserId { get; set; }
    public string FileName { get; set; }
    public string Hash { get; set; }
}
