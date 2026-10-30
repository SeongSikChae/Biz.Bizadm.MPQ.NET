using System.Buffers.Binary;
using SharpCompress.Compressors.LZMA;

namespace Biz.Bizadm.MPQ.NET.Compression;

/// <summary>
/// LZMA as written by StormLib Compress_LZMA: [filter byte 0][5-byte properties][8-byte uncompressed size LE]
/// followed by a raw LZMA stream without end marker.
/// </summary>
internal static class LzmaCodec
{
    private const int PropertiesSize = 5;
    private const int HeaderSize = 1 + PropertiesSize + 8;

    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // StormLib: at least one byte after the header, and blocks with a filter are not accepted.
        if (input.Length <= HeaderSize || input[0] != 0)
            throw new InvalidDataException("Invalid LZMA block header.");

        try
        {
            byte[] properties = input.Slice(1, PropertiesSize).ToArray();
            var data = new MemoryStream(input[HeaderSize..].ToArray(), writable: false);
            using var lzma = LzmaStream.Create(properties, data, data.Length, output.Length, leaveOpen: false);
            return lzma.ReadAtLeast(output, output.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is not (InvalidDataException or OutOfMemoryException))
        {
            throw new InvalidDataException("Corrupt LZMA data.", ex);
        }
    }

    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        var data = new MemoryStream();
        byte[] properties;
        using (var lzma = LzmaStream.Create(new LzmaEncoderProperties(eos: false), isLzma2: false, data))
        {
            properties = lzma.Properties;
            lzma.Write(input);
        }

        var output = new byte[HeaderSize + data.Length];
        properties.AsSpan(0, PropertiesSize).CopyTo(output.AsSpan(1));
        BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(1 + PropertiesSize), (uint)input.Length);
        data.GetBuffer().AsSpan(0, (int)data.Length).CopyTo(output.AsSpan(HeaderSize));
        return output;
    }
}
