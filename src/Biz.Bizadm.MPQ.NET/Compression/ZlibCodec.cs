using System.IO.Compression;

namespace Biz.Bizadm.MPQ.NET.Compression;

/// <summary>zlib (RFC 1950) streams, as written by StormLib Compress_ZLIB.</summary>
internal static class ZlibCodec
{
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output)
    {
        using var source = new MemoryStream(input.ToArray(), writable: false);
        using var zlib = new ZLibStream(source, CompressionMode.Decompress);
        return zlib.ReadAtLeast(output, output.Length, throwOnEndOfStream: false);
    }
}
