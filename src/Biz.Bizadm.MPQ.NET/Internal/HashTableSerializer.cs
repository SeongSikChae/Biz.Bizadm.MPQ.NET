using System.Runtime.InteropServices;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Hash table entry (StormLib TMPQHash, 16 bytes).</summary>
internal readonly record struct MpqHashEntry(uint HashA, uint HashB, ushort Locale, byte Platform, byte Flags, uint BlockIndex)
{
    public const uint Free = 0xFFFFFFFF;
    public const uint Deleted = 0xFFFFFFFE;
    public const uint BlockIndexMask = 0x0FFFFFFF;
}

internal static class HashTableSerializer
{
    public const int EntrySize = 16;

    /// <summary>Plain (not yet encrypted) table bytes.</summary>
    public static byte[] Serialize(IReadOnlyList<MpqHashEntry> entries)
    {
        var table = new byte[entries.Count * EntrySize];
        for (int i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var raw = table.AsSpan(i * EntrySize, EntrySize);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw, entry.HashA);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw[4..], entry.HashB);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw[8..],
                entry.Locale | ((uint)entry.Platform << 16) | ((uint)entry.Flags << 24));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw[12..], entry.BlockIndex);
        }
        return table;
    }

    /// <summary>Parses a decrypted (and decompressed) hash table.</summary>
    public static MpqHashEntry[] Parse(ReadOnlySpan<byte> table)
    {
        ReadOnlySpan<uint> raw = MemoryMarshal.Cast<byte, uint>(table[..(table.Length / EntrySize * EntrySize)]);
        var entries = new MpqHashEntry[raw.Length / 4];
        for (int i = 0; i < entries.Length; i++)
        {
            uint localePlatform = raw[i * 4 + 2];
            entries[i] = new MpqHashEntry(
                raw[i * 4],
                raw[i * 4 + 1],
                (ushort)localePlatform,
                (byte)(localePlatform >> 16),
                (byte)(localePlatform >> 24),
                raw[i * 4 + 3]);
        }
        return entries;
    }
}
