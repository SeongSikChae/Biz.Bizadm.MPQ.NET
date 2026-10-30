using System.Buffers;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

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
        [MpqCompressionType.BZip2] = BZip2Codec.Decompress,
        [MpqCompressionType.Lzma] = LzmaCodec.Decompress,
        [MpqCompressionType.Sparse] = SparseCodec.Decompress,
        [MpqCompressionType.Pkware] = PkwareCodec.Decompress,
        [MpqCompressionType.Huffman] = HuffmanCodec.Decompress,
        [MpqCompressionType.AdpcmMono] = (input, output) => AdpcmCodec.Decompress(input, output, channels: 1),
        [MpqCompressionType.AdpcmStereo] = (input, output) => AdpcmCodec.Decompress(input, output, channels: 2),
    };

    // StormLib cmp_table order (compression).
    private static readonly MpqCompressionType[] CompressOrder =
    [
        MpqCompressionType.Sparse,
        MpqCompressionType.AdpcmMono,
        MpqCompressionType.AdpcmStereo,
        MpqCompressionType.Huffman,
        MpqCompressionType.Zlib,
        MpqCompressionType.Pkware,
        MpqCompressionType.BZip2,
    ];

    // v2+ archives can only be read back with these masks (StormLib SCompDecompress2).
    private static readonly HashSet<MpqCompressionType> V2Masks =
    [
        MpqCompressionType.Zlib, MpqCompressionType.Pkware, MpqCompressionType.BZip2, MpqCompressionType.Lzma,
        MpqCompressionType.Sparse, MpqCompressionType.Sparse | MpqCompressionType.Zlib,
        MpqCompressionType.Sparse | MpqCompressionType.BZip2,
        MpqCompressionType.AdpcmMono | MpqCompressionType.Huffman,
        MpqCompressionType.AdpcmStereo | MpqCompressionType.Huffman,
    ];

    /// <summary>Throws when <paramref name="mask"/> cannot be used for sectors of the given archive version.</summary>
    public static void ValidateMask(MpqCompressionType mask, MpqFormatVersion version)
    {
        if (mask == MpqCompressionType.Lzma)
        {
            if (version < MpqFormatVersion.Version2)
                throw new NotSupportedException("LZMA requires a v2+ archive (in v1, 0x12 means BZip2 | Zlib).");
            return;
        }
        if (mask == MpqCompressionType.None || ((byte)mask & ~CompressOrder.Aggregate(0, (all, m) => all | (byte)m)) != 0)
            throw new ArgumentException($"Invalid compression mask 0x{(byte)mask:X2}.", nameof(mask));
        if (version >= MpqFormatVersion.Version2 && !V2Masks.Contains(mask))
            throw new NotSupportedException($"Compression mask 0x{(byte)mask:X2} cannot be read from v2+ archives.");
    }

    /// <summary>
    /// StormLib SCompCompress: applies each masked method in cmp_table order; a method that does not save at least
    /// 2 bytes is skipped. Returns the mask byte + data, or a copy of the input when nothing helped.
    /// The caller stores the sector raw when the result is not smaller than the input.
    /// </summary>
    public static byte[] Compress(ReadOnlySpan<byte> input, MpqCompressionType mask)
    {
        if (input.IsEmpty)
            return [];

        MpqCompressionType[] steps = mask == MpqCompressionType.Lzma
            ? [MpqCompressionType.Lzma]
            : CompressOrder.Where(step => ((byte)mask & (byte)step) != 0).ToArray();

        byte[] current = input.ToArray();
        byte applied = 0;
        int huffmanType = 0;
        foreach (var step in steps)
        {
            byte[] output = step switch
            {
                MpqCompressionType.Sparse => SparseCodec.Compress(current),
                // StormLib WriteDataToMpqFile passes level 4 for ADPCM: bit shift 5, then Huffman type 7.
                MpqCompressionType.AdpcmMono => AdpcmCodec.Compress(current, channels: 1, bitShift: 5),
                MpqCompressionType.AdpcmStereo => AdpcmCodec.Compress(current, channels: 2, bitShift: 5),
                MpqCompressionType.Huffman => HuffmanCodec.Compress(current, huffmanType),
                MpqCompressionType.Zlib => ZlibCodec.Compress(current),
                MpqCompressionType.Pkware => PkwareCodec.Compress(current),
                MpqCompressionType.BZip2 => BZip2Codec.Compress(current),
                MpqCompressionType.Lzma => LzmaCodec.Compress(current),
                _ => throw new NotSupportedException($"Compression {step} is not supported."),
            };
            if (step is MpqCompressionType.AdpcmMono or MpqCompressionType.AdpcmStereo)
                huffmanType = 7;

            if (output.Length <= current.Length - 2)
            {
                current = output;
                applied |= (byte)step;
            }
        }

        if (applied == 0)
            return input.ToArray();
        return [(mask == MpqCompressionType.Lzma ? (byte)MpqCompressionType.Lzma : applied), .. current];
    }

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
            : Apply(SplitV1(mask), data, output, rejectEmptyOutput: true);
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
        return Apply(steps, data, output, rejectEmptyOutput: false);
    }

    private static MpqCompressionType[] SplitV1(MpqCompressionType mask)
    {
        var steps = V1Order.Where(step => ((byte)mask & (byte)step) != 0).ToArray();
        byte known = steps.Aggregate((byte)0, (all, step) => (byte)(all | (byte)step));
        if (steps.Length == 0 || known != (byte)mask)
            throw new InvalidDataException($"Unknown compression mask 0x{(byte)mask:X2}.");
        return steps;
    }

    /// <summary>
    /// Applies the decompressions in order; each step may produce up to the expected size. StormLib treats a step
    /// producing no data as corrupt only for v1 (SCompDecompressInternal); v2+ (SCompDecompress2) accepts it.
    /// </summary>
    private static int Apply(MpqCompressionType[] steps, ReadOnlySpan<byte> data, Span<byte> output, bool rejectEmptyOutput)
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
                if (written == 0 && rejectEmptyOutput)
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
