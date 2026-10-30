namespace Biz.Bizadm.MPQ.NET.Internal;

internal static class MpqStreamExtensions
{
    /// <summary>Reads exactly <paramref name="buffer"/>.Length bytes at an absolute position.</summary>
    public static void ReadExactlyAt(this Stream stream, long position, Span<byte> buffer)
    {
        stream.Position = position;
        stream.ReadExactly(buffer);
    }
}
