namespace Biz.Bizadm.MPQ.NET.Internal;

internal static class MpqStreamExtensions
{
    /// <summary>Reads exactly <paramref name="buffer"/>.Length bytes at an absolute position.</summary>
    /// <exception cref="InvalidDataException">The range lies outside the stream (positions come from the archive).</exception>
    public static void ReadExactlyAt(this Stream stream, long position, Span<byte> buffer)
    {
        if (position < 0 || position > stream.Length - buffer.Length)
            throw new InvalidDataException("Archive data lies outside the file.");
        stream.Position = position;
        stream.ReadExactly(buffer);
    }
}
