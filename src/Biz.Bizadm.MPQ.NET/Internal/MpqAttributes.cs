using System.Buffers.Binary;

namespace Biz.Bizadm.MPQ.NET.Internal;

[Flags]
internal enum MpqAttributeFlags : uint
{
    None = 0,
    Crc32 = 0x01,
    FileTime = 0x02,
    Md5 = 0x04,
    PatchBit = 0x08,
    All = 0x0F,
}

/// <summary>The "(attributes)" file (StormLib SFileAttributes.cpp): per-block CRC32, FILETIME, MD5 and patch bits.</summary>
internal static class MpqAttributes
{
    public const uint Version = 100;
    private const int HeaderSize = 8;
    private const int Md5Size = 16;

    /// <summary>
    /// Parses the file and stores the values in the first entries. <paramref name="blockTableSize"/> is the number of
    /// block table entries; the file may describe that many entries or one less (StormLib CheckSizeOfAttributesFile).
    /// </summary>
    /// <returns>The attribute flags.</returns>
    public static MpqAttributeFlags Apply(ReadOnlySpan<byte> data, int blockTableSize, IReadOnlyList<MpqFileEntry> entries)
    {
        if (data.Length < HeaderSize || BinaryPrimitives.ReadUInt32LittleEndian(data) != Version)
            throw new InvalidDataException("Invalid (attributes) header.");
        var flags = (MpqAttributeFlags)BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        if ((flags & ~MpqAttributeFlags.All) != 0)
            throw new InvalidDataException("Invalid (attributes) flags.");

        int count = EntryCount(data.Length, flags, blockTableSize);
        if (count > entries.Count)
            throw new InvalidDataException("(attributes) describes more files than the archive has.");

        var rest = data[HeaderSize..];
        if (flags.HasFlag(MpqAttributeFlags.Crc32))
        {
            for (int i = 0; i < count; i++)
                entries[i].Crc32 = BinaryPrimitives.ReadUInt32LittleEndian(rest[(i * 4)..]);
            rest = rest[(count * 4)..];
        }
        if (flags.HasFlag(MpqAttributeFlags.FileTime))
        {
            for (int i = 0; i < count; i++)
                entries[i].FileTime = BinaryPrimitives.ReadInt64LittleEndian(rest[(i * 8)..]);
            rest = rest[(count * 8)..];
        }
        if (flags.HasFlag(MpqAttributeFlags.Md5))
        {
            for (int i = 0; i < count; i++)
                entries[i].Md5 = rest.Slice(i * Md5Size, Md5Size).ToArray();
            rest = rest[(count * Md5Size)..];
        }

        // Patch bits are only used when exactly (count + 7) / 8 bytes remain; MSB first.
        if (flags.HasFlag(MpqAttributeFlags.PatchBit) && rest.Length == (count + 7) / 8)
        {
            for (int i = 0; i < count; i++)
            {
                if ((rest[i / 8] & (0x80 >> (i % 8))) != 0)
                    entries[i].Flags |= MpqFileFlags.PatchFile;
            }
        }
        return flags;
    }

    /// <summary>StormLib CreateAttributesFile for the first <paramref name="blockTableSize"/> entries.</summary>
    public static byte[] Serialize(MpqAttributeFlags flags, IReadOnlyList<MpqFileEntry> entries, int blockTableSize)
    {
        if (Enumerable.Range(0, blockTableSize).Any(i => entries[i].Flags.HasFlag(MpqFileFlags.PatchFile)))
            flags |= MpqAttributeFlags.PatchBit;

        var output = new byte[GetSize(flags, blockTableSize)];
        BinaryPrimitives.WriteUInt32LittleEndian(output, Version);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4), (uint)(flags & MpqAttributeFlags.All));
        int pos = HeaderSize;

        if (flags.HasFlag(MpqAttributeFlags.Crc32))
        {
            for (int i = 0; i < blockTableSize; i++, pos += 4)
                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(pos), entries[i].Crc32);
        }
        if (flags.HasFlag(MpqAttributeFlags.FileTime))
        {
            for (int i = 0; i < blockTableSize; i++, pos += 8)
                BinaryPrimitives.WriteInt64LittleEndian(output.AsSpan(pos), entries[i].FileTime);
        }
        if (flags.HasFlag(MpqAttributeFlags.Md5))
        {
            for (int i = 0; i < blockTableSize; i++, pos += Md5Size)
                entries[i].Md5?.AsSpan(0, Md5Size).CopyTo(output.AsSpan(pos));
        }
        if (flags.HasFlag(MpqAttributeFlags.PatchBit))
        {
            // Written as (count + 6) / 8 bytes, so the last bit can fall outside (Blizzard behavior).
            for (int i = 0; i < blockTableSize; i++)
            {
                if (entries[i].Flags.HasFlag(MpqFileFlags.PatchFile) && pos + i / 8 < output.Length)
                    output[pos + i / 8] |= (byte)(0x80 >> (i % 8));
            }
        }
        return output;
    }

    /// <summary>Largest valid (attributes) for <paramref name="blockTableSize"/> entries (all flags, DWORD patch array variant).</summary>
    public static long MaxSize(int blockTableSize) => HeaderSize + blockTableSize * (4L + 8 + Md5Size + 4);

    /// <summary>StormLib GetSizeOfAttributesFile.</summary>
    private static int GetSize(MpqAttributeFlags flags, int count)
    {
        long size = HeaderSize;
        if (flags.HasFlag(MpqAttributeFlags.Crc32))
            size += count * 4L;
        if (flags.HasFlag(MpqAttributeFlags.FileTime))
            size += count * 8L;
        if (flags.HasFlag(MpqAttributeFlags.Md5))
            size += count * (long)Md5Size;
        if (flags.HasFlag(MpqAttributeFlags.PatchBit))
            size += (count + 6) / 8;
        return checked((int)size);
    }

    /// <summary>StormLib CheckSizeOfAttributesFile: full count, one less, missing patch bits, or DWORD patch array.</summary>
    private static int EntryCount(long size, MpqAttributeFlags flags, int blockTableSize)
    {
        long n = blockTableSize;
        long PerEntry() =>
            (flags.HasFlag(MpqAttributeFlags.Crc32) ? 4 : 0)
            + (flags.HasFlag(MpqAttributeFlags.FileTime) ? 8 : 0)
            + (flags.HasFlag(MpqAttributeFlags.Md5) ? Md5Size : 0);
        long patchBits = flags.HasFlag(MpqAttributeFlags.PatchBit) ? (n + 6) / 8 : 0;

        if (size == HeaderSize + n * PerEntry() + patchBits)
            return blockTableSize;
        if (n > 0 && size == HeaderSize + (n - 1) * PerEntry() + patchBits)
            return blockTableSize - 1;
        if (size == HeaderSize + n * PerEntry())
            return blockTableSize;
        if (flags.HasFlag(MpqAttributeFlags.PatchBit) && size == HeaderSize + n * PerEntry() + n * 4)
            return blockTableSize;
        throw new InvalidDataException("Unexpected (attributes) size.");
    }
}
