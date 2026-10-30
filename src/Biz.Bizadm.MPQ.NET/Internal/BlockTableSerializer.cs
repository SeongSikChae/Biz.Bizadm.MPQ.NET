using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Biz.Bizadm.MPQ.NET.Internal;

internal static class BlockTableSerializer
{
    public const int EntrySize = 16;

    /// <summary>Writes decrypted block entries (StormLib TMPQBlock) into the first entries of <paramref name="entries"/>.</summary>
    public static void Parse(ReadOnlySpan<byte> table, MpqFileEntry[] entries)
    {
        int count = Math.Min(table.Length / EntrySize, entries.Length);
        for (int i = 0; i < count; i++)
        {
            var raw = table.Slice(i * EntrySize, EntrySize);
            var entry = entries[i];
            entry.FilePosition = BinaryPrimitives.ReadUInt32LittleEndian(raw);
            entry.CompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(raw[4..]);
            entry.FileSize = BinaryPrimitives.ReadUInt32LittleEndian(raw[8..]);
            entry.Flags = (MpqFileFlags)BinaryPrimitives.ReadUInt32LittleEndian(raw[12..]);
        }
    }

    /// <summary>
    /// Adds the high 16 bits of each file position from the hi-block table (v2+; not encrypted nor compressed),
    /// as StormLib does after loading the block table.
    /// </summary>
    public static void ApplyHiBlockTable(Stream stream, long position, MpqFileEntry[] entries, int count,
        ReadOnlyMemory<byte> md5, bool strict)
    {
        var hi = new ushort[count];
        var bytes = MemoryMarshal.AsBytes(hi.AsSpan());
        stream.ReadExactlyAt(position, bytes);
        MpqTableReader.VerifyMd5(bytes, md5, strict, "hi-block table");
        for (int i = 0; i < count; i++)
            entries[i].FilePosition |= (long)hi[i] << 32;
    }
}
