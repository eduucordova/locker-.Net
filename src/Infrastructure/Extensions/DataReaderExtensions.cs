using System.Data;

namespace Infrastructure.Extensions;

internal static class DataReaderExtensions
{
    public static IEnumerable<T> ReadAs<T>(this IDataReader reader) where T : new()
    {
        while (reader.Read())
        {
            var obj = new T();

            foreach (var property in typeof(T).GetProperties())
            {
                var value = reader[property.Name];
                property.SetValue(obj, value, null);
            }

            yield return obj;
        }
    }
}
