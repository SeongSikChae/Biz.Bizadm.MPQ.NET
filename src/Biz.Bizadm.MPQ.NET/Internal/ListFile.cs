using System.Text;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>The "(listfile)" format (StormLib SFileListFile.cpp).</summary>
internal static class ListFile
{
    public const string ListFileName = "(listfile)";
    public const string AttributesName = "(attributes)";
    public const string SignatureName = "(signature)";

    /// <summary>StormLib MAX_LISTFILE_SIZE (192 MB).</summary>
    public const long MaxSize = 0xC000000;

    /// <summary>
    /// StormLib ReadListFileLine: lines are separated by CR and/or LF only; spaces and tabs are part of the name,
    /// empty lines are skipped. Names are decoded as UTF-8.
    /// </summary>
    public static List<string> Parse(ReadOnlySpan<byte> data)
    {
        var names = new List<string>();
        while (!data.IsEmpty)
        {
            int end = data.IndexOfAny((byte)'\r', (byte)'\n');
            var line = end < 0 ? data : data[..end];
            if (!line.IsEmpty)
                names.Add(Encoding.UTF8.GetString(line));
            data = end < 0 ? default : data[(end + 1)..];
        }
        return names;
    }

    /// <summary>
    /// StormLib CreateListFile: names sorted with _stricmp (ASCII case-insensitive, byte order), case-insensitive
    /// duplicates removed, internal and pseudo names excluded, each line terminated by CRLF.
    /// </summary>
    public static byte[] Serialize(IEnumerable<string> names)
    {
        var sorted = names
            .Where(name => !IsInternalName(name) && !IsPseudoName(name))
            .Select(Encoding.UTF8.GetBytes)
            .ToList();
        sorted.Sort(CompareIgnoreAsciiCase);

        using var output = new MemoryStream();
        byte[]? previous = null;
        foreach (byte[] name in sorted)
        {
            if (previous is not null && CompareIgnoreAsciiCase(previous, name) == 0)
                continue;
            output.Write(name);
            output.Write("\r\n"u8);
            previous = name;
        }
        return output.ToArray();
    }

    /// <summary>StormLib IsInternalMpqFileName.</summary>
    public static bool IsInternalName(string name) =>
        name.Equals(ListFileName, StringComparison.OrdinalIgnoreCase)
        || name.Equals(AttributesName, StringComparison.OrdinalIgnoreCase)
        || name.Equals(SignatureName, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A name a new file can get: it must survive the (listfile) — line breaks would split it and NUL ends it — and must
    /// not be a StormLib pseudo name, which the (listfile) leaves out.
    /// </summary>
    /// <exception cref="ArgumentException">The name cannot be stored.</exception>
    public static void ValidateNewName(string name, string paramName)
    {
        if (name.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
            throw new ArgumentException("File names cannot contain line breaks or NUL characters.", paramName);
        if (IsPseudoName(name))
            throw new ArgumentException($"'{name}' has the form of a StormLib pseudo name (File########.ext).", paramName);
    }

    /// <summary>StormLib IsPseudoFileName: "File########.ext".</summary>
    public static bool IsPseudoName(string name) =>
        name.Length >= 13
        && name.StartsWith("File", StringComparison.OrdinalIgnoreCase)
        && name.AsSpan(4, 8).IndexOfAnyExceptInRange('0', '9') < 0
        && name[12] == '.';

    /// <summary>_stricmp on bytes: ASCII letters compared as lower case, other bytes by value.</summary>
    private static int CompareIgnoreAsciiCase(byte[] x, byte[] y)
    {
        int length = Math.Min(x.Length, y.Length);
        for (int i = 0; i < length; i++)
        {
            int a = ToLower(x[i]), b = ToLower(y[i]);
            if (a != b)
                return a - b;
        }
        return x.Length - y.Length;
    }

    private static int ToLower(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? b + 0x20 : b;
}
