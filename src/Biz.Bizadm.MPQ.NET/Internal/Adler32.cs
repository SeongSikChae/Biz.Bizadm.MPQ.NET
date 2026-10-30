namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>zlib adler32, used for sector checksums (MPQ_FILE_SECTOR_CRC).</summary>
internal static class Adler32
{
    private const uint Modulus = 65521;

    /// <summary>zlib adler32(0, data, len) as called by StormLib (note: the initial value 0, not 1).</summary>
    public static uint Compute(ReadOnlySpan<byte> data, uint adler = 0)
    {
        uint a = adler & 0xFFFF, b = adler >> 16;
        foreach (byte value in data)
        {
            a = (a + value) % Modulus;
            b = (b + a) % Modulus;
        }
        return (b << 16) | a;
    }
}
