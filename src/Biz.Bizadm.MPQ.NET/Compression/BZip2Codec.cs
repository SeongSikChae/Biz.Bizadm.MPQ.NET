using SharpCompress.Compressors;
using SharpCompress.Compressors.BZip2;

namespace Biz.Bizadm.MPQ.NET.Compression;

/// <summary>Standard bzip2 streams (StormLib Compress_BZIP2 / Decompress_BZIP2), via SharpCompress.</summary>
internal static class BZip2Codec
{
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output)
    {
        try
        {
            using var bzip2 = BZip2Stream.Create(new MemoryStream(input.ToArray(), writable: false), CompressionMode.Decompress,
                decompressConcatenated: false, leaveOpen: false, tolerateTruncatedStream: false);
            return bzip2.ReadAtLeast(output, output.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            throw new InvalidDataException("Corrupt bzip2 data.", ex);
        }
    }

    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        var output = new MemoryStream();
        using (var bzip2 = BZip2Stream.Create(output, CompressionMode.Compress,
            decompressConcatenated: false, leaveOpen: true, tolerateTruncatedStream: false))
        {
            bzip2.Write(input);
        }
        return output.ToArray();
    }
}
