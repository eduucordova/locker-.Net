using Infrastructure.Contexts;
using Unit.Tests.Infrastructure.Utils;

namespace Unit.Tests.Infrastructure;

public class FileDbContextTests : IClassFixture<DbTestsContextFixture>
{
    private FilesContext _filesContext;

    public FileDbContextTests(DbTestsContextFixture data)
    {
        _filesContext = new FilesContext(data.DataSource);
        data.SetContext<FilesContext>(_filesContext);
    }
}
