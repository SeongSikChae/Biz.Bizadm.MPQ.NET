namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Little-endian bit fields used by HET/BET tables (StormLib TMPQBits::GetBits).</summary>
internal static class MpqBitArray
{
    /// <summary>Reads <paramref name="bitCount"/> bits (at most 64) starting at <paramref name="bitPosition"/>.</summary>
    /// <exception cref="InvalidDataException">The range is outside the array.</exception>
    public static ulong GetBits(ReadOnlySpan<byte> bits, long bitPosition, int bitCount)
    {
        if (bitCount is < 0 or > 64 || bitPosition < 0 || bitPosition + bitCount > (long)bits.Length * 8)
            throw new InvalidDataException("Bit field is outside the table.");

        ulong value = 0;
        for (int i = 0; i < bitCount; i++)
        {
            long position = bitPosition + i;
            if (((bits[(int)(position >> 3)] >> (int)(position & 7)) & 1) != 0)
                value |= 1UL << i;
        }
        return value;
    }

    /// <summary>Writes the low <paramref name="bitCount"/> bits of <paramref name="value"/> (StormLib TMPQBits::SetBits).</summary>
    public static void SetBits(Span<byte> bits, long bitPosition, int bitCount, ulong value)
    {
        if (bitCount is < 0 or > 64 || bitPosition < 0 || bitPosition + bitCount > (long)bits.Length * 8)
            throw new ArgumentOutOfRangeException(nameof(bitPosition), "Bit field is outside the table.");

        for (int i = 0; i < bitCount; i++)
        {
            long position = bitPosition + i;
            byte mask = (byte)(1 << (int)(position & 7));
            if (((value >> i) & 1) != 0)
                bits[(int)(position >> 3)] |= mask;
            else
                bits[(int)(position >> 3)] &= (byte)~mask;
        }
    }

    /// <summary>StormLib GetNecessaryBitCount.</summary>
    public static int BitCount(ulong maxValue) => 64 - System.Numerics.BitOperations.LeadingZeroCount(maxValue);
}
