// Ported from StormLib sparse/sparse.cpp.
// StormLib - MIT License, Copyright (c) 1999-2013 Ladislav Zezula.

namespace Biz.Bizadm.MPQ.NET.Compression.Legacy;

/// <summary>
/// Blizzard sparse (zero run) compression: a 4-byte big-endian size, then chunks:
/// 0x80|(n-1) followed by n literal bytes, or (n-3) for n zero bytes.
/// </summary>
internal static class SparseCodec
{
    /// <summary>
    /// Lenient version of StormLib DecompressSparse: a literal chunk longer than the remaining input is cut to it.
    /// StormLib v9.40 CompressSparse terminates with 0xFF followed by only 1-3 bytes when one of the last 3 input
    /// bytes is nonzero, which its own decompressor rejects.
    /// </summary>
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < 5)
            throw new InvalidDataException("Sparse data is too short.");

        int size = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
        if (size < 0 || size > output.Length)
            throw new InvalidDataException($"Sparse size {size} exceeds the output buffer.");

        int pos = 4, written = 0;
        while (pos < input.Length)
        {
            byte control = input[pos++];
            int count;
            if ((control & 0x80) != 0)
            {
                count = Math.Min(Math.Min((control & 0x7F) + 1, input.Length - pos), size - written);
                input.Slice(pos, count).CopyTo(output[written..]);
                pos += count;
            }
            else
            {
                count = Math.Min((control & 0x7F) + 3, size - written);
                output.Slice(written, count).Clear();
            }
            written += count;
        }

        // StormLib leaves a gap when the input ends early; clear it so the result does not depend on the buffer.
        output[written..size].Clear();
        return size;
    }

    /// <summary>
    /// StormLib CompressSparse, except that the final 1-3 bytes use the correct 0x80|(n-1) marker instead of 0xFF.
    /// The result can be larger than the input; the caller keeps the smaller representation.
    /// </summary>
    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        var output = new List<byte>(input.Length / 2 + 8)
        {
            (byte)(input.Length >> 24), (byte)(input.Length >> 16), (byte)(input.Length >> 8), (byte)input.Length,
        };

        int pos = 0, end = input.Length;
        while (pos < end - 3)
        {
            int lastNonZero = pos, scan = pos, zeros = 0;
            for (; scan < end; scan++)
            {
                if (input[scan] == 0)
                {
                    zeros++;
                }
                else
                {
                    if (zeros >= 3)
                        break;
                    lastNonZero = scan + 1;
                    zeros = 0;
                }
            }

            int nonZeros = lastNonZero - pos;
            while (nonZeros > 0x81)
            {
                output.Add(0xFF);
                AddRange(output, input.Slice(pos, 0x80));
                nonZeros -= 0x80;
                pos += 0x80;
            }

            // StormLib (matching Blizzard): 0x81 remaining nonzeros are written as 1 + 0x80.
            if (nonZeros > 0x80)
            {
                output.Add(0x80);
                output.Add(input[pos]);
                nonZeros--;
                pos++;
            }

            if (nonZeros >= 1)
            {
                output.Add((byte)(0x80 | (nonZeros - 1)));
                AddRange(output, input.Slice(pos, nonZeros));
                pos += nonZeros;
            }

            while (zeros > 0x85)
            {
                output.Add(0x7F);
                zeros -= 0x82;
                pos += 0x82;
            }

            if (zeros > 0x82)
            {
                output.Add(0x00);
                zeros -= 3;
                pos += 3;
            }

            if (zeros >= 3)
            {
                output.Add((byte)(zeros - 3));
                pos += zeros;
            }
        }

        // Flush the last (up to 3) bytes.
        if (pos < end)
        {
            ReadOnlySpan<byte> tail = input[pos..];
            if (tail.IndexOfAnyExcept((byte)0) >= 0)
            {
                output.Add((byte)(0x80 | (tail.Length - 1)));
                AddRange(output, tail);
            }
            else
            {
                output.Add(0x7F);
            }
        }

        return [.. output];
    }

    private static void AddRange(List<byte> list, ReadOnlySpan<byte> bytes)
    {
        foreach (byte b in bytes)
            list.Add(b);
    }
}
