using System.Runtime.InteropServices;

namespace Biz.Bizadm.MPQ.NET.Internal;

internal static class BlockTableSerializer
{
    public const int EntrySize = 16;

    /// <summary>Reads and decrypts <paramref name="count"/> block entries (StormLib TMPQBlock) at an absolute stream position.</summary>
    public static MpqFileEntry[] Read(Stream stream, long position, uint count)
    {
        var raw = new uint[count * 4];
        stream.ReadExactlyAt(position, MemoryMarshal.AsBytes(raw.AsSpan()));
        StormCrypto.DecryptBlock(raw, StormCrypto.BlockTableKey);

        var entries = new MpqFileEntry[count];
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i] = new MpqFileEntry
            {
                FilePosition = raw[i * 4],
                CompressedSize = raw[i * 4 + 1],
                FileSize = raw[i * 4 + 2],
                Flags = (MpqFileFlags)raw[i * 4 + 3],
            };
        }
        return entries;
    }
}
