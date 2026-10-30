using System.Buffers;

namespace Biz.Bizadm.MPQ.NET.Compression;

/// <summary>Decompresses one sector into a buffer of the expected size and returns the number of bytes written.</summary>
internal delegate int Decompressor(ReadOnlySpan<byte> input, Span<byte> output);

/// <summary>
/// Sector decompression by compression mask, following StormLib SCompDecompressX:
/// v1 archives apply every masked method in a fixed order, v2+ archives accept only a fixed set of masks.
/// </summary>
internal static class MpqCompression
{
    private static readonly Dictionary<MpqCompressionType, Decompressor> Codecs = new()
    {
        [MpqCompressionType.Zlib] = ZlibCodec.Decompress,
    };

    // StormLib dcmp_table order (v1).
    private static readonly MpqCompressionType[] V1Order =
    [
        MpqCompressionType.BZip2,
        MpqCompressionType.Pkware,
        MpqCompressionType.Zlib,
        MpqCompressionType.Huffman,
        MpqCompressionType.AdpcmStereo,
        MpqCompressionType.AdpcmMono,
        MpqCompressionType.Sparse,
    ];

    /// <summary>
    /// Decompresses <paramref name="input"/> (mask byte + data) into <paramref name="output"/>, whose length is the
    /// expected size. Input of the same length as the output is stored uncompressed and copied.
    /// </summary>
    /// <exception cref="InvalidDataException">The mask is not valid for the format version or the data is corrupt.</exception>
    /// <exception cref="NotSupportedException">A codec in the mask is not available.</exception>
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output, MpqFormatVersion version)
    {
        if (input.Length == output.Length)
        {
            input.CopyTo(output);
            return output.Length;
        }
        if (input.Length == 0 || input.Length > output.Length)
            throw new InvalidDataException($"Invalid compressed sector size {input.Length} for {output.Length} bytes.");

        var mask = (MpqCompressionType)input[0];
        var data = input[1..];
        return version >= MpqFormatVersion.Version2
            ? DecompressV2(mask, data, output)
            : Apply(SplitV1(mask), data, output);
    }

    private static int DecompressV2(MpqCompressionType mask, ReadOnlySpan<byte> data, Span<byte> output)
    {
        MpqCompressionType[] steps = mask switch
        {
            MpqCompressionType.Zlib or MpqCompressionType.Pkware or MpqCompressionType.BZip2
                or MpqCompressionType.Lzma or MpqCompressionType.Sparse => [mask],
            MpqCompressionType.Sparse | MpqCompressionType.Zlib => [MpqCompressionType.Zlib, MpqCompressionType.Sparse],
            MpqCompressionType.Sparse | MpqCompressionType.BZip2 => [MpqCompressionType.BZip2, MpqCompressionType.Sparse],
            MpqCompressionType.AdpcmMono | MpqCompressionType.Huffman => [MpqCompressionType.Huffman, MpqCompressionType.AdpcmMono],
            MpqCompressionType.AdpcmStereo | MpqCompressionType.Huffman => [MpqCompressionType.Huffman, MpqCompressionType.AdpcmStereo],
            _ => throw new InvalidDataException($"Compression mask 0x{(byte)mask:X2} is not valid in v2+ archives."),
        };
        return Apply(steps, data, output);
    }

    private static MpqCompressionType[] SplitV1(MpqCompressionType mask)
    {
        var steps = V1Order.Where(step => ((byte)mask & (byte)step) != 0).ToArray();
        byte known = steps.Aggregate((byte)0, (all, step) => (byte)(all | (byte)step));
        if (steps.Length == 0 || known != (byte)mask)
            throw new InvalidDataException($"Unknown compression mask 0x{(byte)mask:X2}.");
        return steps;
    }

    /// <summary>Applies the decompressions in order; each step may produce up to the expected size.</summary>
    private static int Apply(MpqCompressionType[] steps, ReadOnlySpan<byte> data, Span<byte> output)
    {
        foreach (var step in steps)
        {
            if (!Codecs.ContainsKey(step))
                throw new NotSupportedException($"Compression {step} is not supported.");
        }

        byte[]? work = steps.Length > 1 ? ArrayPool<byte>.Shared.Rent(output.Length) : null;
        byte[]? next = steps.Length > 2 ? ArrayPool<byte>.Shared.Rent(output.Length) : null;
        try
        {
            ReadOnlySpan<byte> current = data;
            int written = 0;
            for (int i = 0; i < steps.Length; i++)
            {
                bool last = i == steps.Length - 1;
                Span<byte> target = last ? output : (i % 2 == 0 ? work! : next!).AsSpan(0, output.Length);
                written = Codecs[steps[i]](current, target);
                if (written <= 0)
                    throw new InvalidDataException($"{steps[i]} decompression produced no data.");
                current = target[..written];
            }
            return written;
        }
        finally
        {
            if (work is not null)
                ArrayPool<byte>.Shared.Return(work);
            if (next is not null)
                ArrayPool<byte>.Shared.Return(next);
        }
    }
}
