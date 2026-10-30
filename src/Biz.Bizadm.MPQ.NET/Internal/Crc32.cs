namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>zlib crc32 (IEEE 802.3, reflected polynomial 0xEDB88320), used by (attributes).</summary>
internal static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < table.Length; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    /// <summary>Continues <paramref name="crc"/> (0 to start) over <paramref name="data"/>, like zlib crc32(crc, data, len).</summary>
    public static uint Append(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = ~crc;
        foreach (byte b in data)
            c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        return ~c;
    }

    public static uint Compute(ReadOnlySpan<byte> data) => Append(0, data);
}
