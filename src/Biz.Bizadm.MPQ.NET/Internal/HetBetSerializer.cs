using System.Buffers.Binary;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Parsed HET table (StormLib TMPQHetTable / TranslateHetTable / GetFileIndex_Het).</summary>
internal sealed class HetTable
{
    private const int HeaderSize = 32; // after the 12-byte extended header
    private const byte FreeEntry = 0x00;

    private readonly byte[] _nameHashes;
    private readonly byte[] _indexBits;

    private HetTable(int entryCount, int totalCount, int nameHashBitSize, int indexSizeTotal, int indexSize, byte[] nameHashes, byte[] indexBits)
    {
        EntryCount = entryCount;
        TotalCount = totalCount;
        NameHashBitSize = nameHashBitSize;
        IndexSizeTotal = indexSizeTotal;
        IndexSize = indexSize;
        _nameHashes = nameHashes;
        _indexBits = indexBits;
        AndMask = (nameHashBitSize != 64 ? 1UL << nameHashBitSize : 0) - 1;
        OrMask = 1UL << (nameHashBitSize - 1);
    }

    public int EntryCount { get; }
    public int TotalCount { get; }
    public int NameHashBitSize { get; }
    public int IndexSizeTotal { get; }
    public int IndexSize { get; }
    public ulong AndMask { get; }
    public ulong OrMask { get; }

    public static HetTable Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new InvalidDataException("HET table is too small.");

        uint tableSize = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        uint totalCount = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
        uint nameHashBitSize = BinaryPrimitives.ReadUInt32LittleEndian(data[12..]);
        uint indexSizeTotal = BinaryPrimitives.ReadUInt32LittleEndian(data[16..]);
        uint indexSize = BinaryPrimitives.ReadUInt32LittleEndian(data[24..]);
        uint indexTableSize = BinaryPrimitives.ReadUInt32LittleEndian(data[28..]);

        // StormLib TranslateHetTable size checks.
        if (data.Length < tableSize || (ulong)HeaderSize + totalCount + indexTableSize != tableSize)
            throw new InvalidDataException("Invalid HET table size.");
        if (nameHashBitSize is < 8 or > 64 || indexSize > 32 || indexSize > indexSizeTotal || totalCount == 0 && entryCount != 0)
            throw new InvalidDataException("Invalid HET table header.");

        var body = data[HeaderSize..(int)tableSize];
        return new HetTable((int)entryCount, (int)totalCount, (int)nameHashBitSize, (int)indexSizeTotal, (int)indexSize,
            body[..(int)totalCount].ToArray(), body[(int)totalCount..].ToArray());
    }

    /// <summary>
    /// StormLib RebuildHetTable: CreateHetTable(entry count, 0, 0x40) with every existing entry inserted in file table
    /// order (InsertHetEntry).
    /// </summary>
    public static HetTable Build(IReadOnlyList<MpqFileEntry> entries)
    {
        const int nameHashBitSize = 0x40;
        int totalCount = entries.Count * 4 / 3;
        int indexSize = MpqBitArray.BitCount((ulong)entries.Count);
        var nameHashes = new byte[totalCount];
        var indexBits = new byte[((long)indexSize * totalCount + 7) / 8];
        indexBits.AsSpan().Fill(0xFF);

        for (int fileIndex = 0; fileIndex < entries.Count; fileIndex++)
        {
            if (!entries[fileIndex].Flags.HasFlag(MpqFileFlags.Exists))
                continue;

            ulong nameHash = entries[fileIndex].NameHash;
            int index = (int)(nameHash % (ulong)totalCount);
            while (nameHashes[index] != FreeEntry)
                index = (index + 1) % totalCount; // TotalCount exceeds the number of existing entries
            nameHashes[index] = (byte)(nameHash >> (nameHashBitSize - 8));
            MpqBitArray.SetBits(indexBits, (long)indexSize * index, indexSize, (ulong)fileIndex);
        }

        return new HetTable(entries.Count, totalCount, nameHashBitSize, indexSize, indexSize, nameHashes, indexBits);
    }

    /// <summary>StormLib CreateHetHeader + TranslateHetTable: the table without the 12-byte extended header.</summary>
    public byte[] Serialize()
    {
        var output = new byte[HeaderSize + _nameHashes.Length + _indexBits.Length];
        uint[] fields = [(uint)output.Length, (uint)EntryCount, (uint)TotalCount, (uint)NameHashBitSize,
            (uint)IndexSizeTotal, 0, (uint)IndexSize, (uint)_indexBits.Length];
        for (int i = 0; i < fields.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), fields[i]);
        _nameHashes.CopyTo(output, HeaderSize);
        _indexBits.CopyTo(output, HeaderSize + _nameHashes.Length);
        return output;
    }

    /// <summary>Masked 64-bit name hash as stored in BET entries.</summary>
    public ulong HashName(string name) => (JenkinsHash.HashFileName(name) & AndMask) | OrMask;

    /// <summary>Calls <paramref name="visit"/>(nameHash1, fileIndex) for every occupied slot (indexes are unsigned, as in StormLib).</summary>
    public void ForEachEntry(Action<byte, ulong> visit)
    {
        for (int i = 0; i < TotalCount; i++)
        {
            if (_nameHashes[i] != FreeEntry)
                visit(_nameHashes[i], MpqBitArray.GetBits(_indexBits, (long)IndexSizeTotal * i, IndexSize));
        }
    }

    /// <summary>StormLib GetFileIndex_Het: linear probing from hash % TotalCount until a free slot.</summary>
    public int? FindIndex(ulong fileNameHash, IReadOnlyList<MpqFileEntry> entries)
    {
        if (EntryCount == 0 || TotalCount == 0)
            return null;

        byte nameHash1 = (byte)(fileNameHash >> (NameHashBitSize - 8));
        int start = (int)(fileNameHash % (ulong)TotalCount);
        int index = start;
        while (_nameHashes[index] != FreeEntry)
        {
            if (_nameHashes[index] == nameHash1)
            {
                ulong fileIndex = MpqBitArray.GetBits(_indexBits, (long)IndexSizeTotal * index, IndexSize);
                if (fileIndex < (ulong)entries.Count && entries[(int)fileIndex].NameHash == fileNameHash)
                    return (int)fileIndex;
            }

            index = (index + 1) % TotalCount;
            if (index == start)
                break;
        }
        return null;
    }
}

/// <summary>Parsed BET table (StormLib TranslateBetTable / BuildFileTable_HetBet).</summary>
internal static class BetTable
{
    private const int HeaderSize = 76; // after the 12-byte extended header

    /// <summary>Number of entries declared in the BET header.</summary>
    public static uint ReadEntryCount(byte[] data) =>
        data.Length >= HeaderSize ? BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4)) : 0;

    /// <summary>Fills file positions, sizes, flags and name hashes from the BET table into <paramref name="entries"/>.</summary>
    public static void Apply(byte[] data, HetTable het, MpqFileEntry[] entries)
    {
        if (data.Length < HeaderSize)
            throw new InvalidDataException("BET table is too small.");

        // Header fields are DWORDs (StormLib); keep them unsigned and do the arithmetic in 64 bits.
        uint U(int index) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(index * 4));
        uint tableSize = U(0), entryCount = U(1), entrySize = U(3);
        long indexFilePos = U(4), indexFileSize = U(5), indexCmpSize = U(6), indexFlag = U(7);
        uint countFilePos = U(9), countFileSize = U(10), countCmpSize = U(11), countFlag = U(12);
        long totalNameHash2 = U(14);
        uint countNameHash2 = U(16), flagCount = U(18);

        if (data.Length < tableSize || entryCount > entries.Length)
            throw new InvalidDataException("Invalid BET table size.");
        if (countNameHash2 + 8L != het.NameHashBitSize)
            throw new InvalidDataException("BET name hash size does not match the HET table.");
        if (countFilePos > 64 || countFileSize > 32 || countCmpSize > 32 || countFlag > 32)
            throw new InvalidDataException("Invalid BET field size.");

        long flagsEnd = HeaderSize + flagCount * 4L;
        long fileTableEnd = flagsEnd + (entrySize * (long)entryCount + 7) / 8;
        long nameHashEnd = fileTableEnd + (totalNameHash2 * entryCount + 7) / 8;
        if (nameHashEnd > data.Length)
            throw new InvalidDataException("BET table arrays exceed the table.");

        var flags = data.AsSpan((int)HeaderSize, (int)(flagsEnd - HeaderSize));
        var fileTable = data.AsSpan((int)flagsEnd, (int)(fileTableEnd - flagsEnd));
        byte[] hashBits = data.AsSpan((int)fileTableEnd, (int)(nameHashEnd - fileTableEnd)).ToArray();

        for (int i = 0; i < entryCount; i++)
        {
            long bit = (long)entrySize * i;
            var entry = entries[i];
            entry.FilePosition = (long)MpqBitArray.GetBits(fileTable, bit + indexFilePos, (int)countFilePos);
            entry.FileSize = (uint)MpqBitArray.GetBits(fileTable, bit + indexFileSize, (int)countFileSize);
            entry.CompressedSize = (uint)MpqBitArray.GetBits(fileTable, bit + indexCmpSize, (int)countCmpSize);
            if (flagCount != 0)
            {
                ulong flagIndex = MpqBitArray.GetBits(fileTable, bit + indexFlag, (int)countFlag);
                if (flagIndex >= flagCount)
                    throw new InvalidDataException("BET flag index is out of range.");
                entry.Flags = (MpqFileFlags)BinaryPrimitives.ReadUInt32LittleEndian(flags[(int)(flagIndex * 4)..]);
            }
        }

        // Combine HET NameHash1 with BET NameHash2 into the full masked name hash.
        het.ForEachEntry((nameHash1, fileIndex) =>
        {
            if (fileIndex < entryCount)
            {
                ulong nameHash2 = MpqBitArray.GetBits(hashBits, totalNameHash2 * (long)fileIndex, (int)countNameHash2);
                entries[fileIndex].NameHash = ((ulong)nameHash1 << (int)countNameHash2) | nameHash2;
            }
        });
    }

    /// <summary>
    /// StormLib CreateBetHeader + TranslateBetTable: the table without the 12-byte extended header. Every entry is
    /// stored, also the ones that do not exist; field widths are the bit counts of the largest values.
    /// </summary>
    public static byte[] Serialize(IReadOnlyList<MpqFileEntry> entries, HetTable het)
    {
        // StormLib InitFileFlagArray fills unused slots with 0xCC; one slot is written even without entries.
        var flagArray = new List<uint>();
        int FlagIndex(MpqFileFlags flags)
        {
            int index = flagArray.IndexOf((uint)flags);
            if (index < 0)
            {
                flagArray.Add((uint)flags);
                index = flagArray.Count - 1;
            }
            return index;
        }

        long maxPosition = 0;
        uint maxFileSize = 0, maxCmpSize = 0;
        int maxFlagIndex = 0;
        foreach (var entry in entries)
        {
            maxPosition = Math.Max(maxPosition, entry.FilePosition);
            maxFileSize = Math.Max(maxFileSize, entry.FileSize);
            maxCmpSize = Math.Max(maxCmpSize, entry.CompressedSize);
            maxFlagIndex = Math.Max(maxFlagIndex, FlagIndex(entry.Flags));
        }
        if (flagArray.Count == 0)
            flagArray.Add(0xCCCCCCCC);

        int countFilePos = MpqBitArray.BitCount((ulong)maxPosition);
        int countFileSize = MpqBitArray.BitCount(maxFileSize);
        int countCmpSize = MpqBitArray.BitCount(maxCmpSize);
        int countFlag = MpqBitArray.BitCount((ulong)maxFlagIndex + 1);
        int indexFileSize = countFilePos;
        int indexCmpSize = indexFileSize + countFileSize;
        int indexFlag = indexCmpSize + countCmpSize;
        int entrySize = countFilePos + countFileSize + countCmpSize + countFlag;
        int flagCount = maxFlagIndex + 1;
        int nameHash2 = het.NameHashBitSize - 8;
        long fileTableSize = ((long)entrySize * entries.Count + 7) / 8;
        long nameHashSize = ((long)nameHash2 * entries.Count + 7) / 8;

        var output = new byte[checked((int)(HeaderSize + flagCount * 4L + fileTableSize + nameHashSize))];
        uint[] fields =
        [
            (uint)output.Length, (uint)entries.Count, 0x10, (uint)entrySize,
            0, (uint)indexFileSize, (uint)indexCmpSize, (uint)indexFlag, (uint)(indexFlag + countFlag),
            (uint)countFilePos, (uint)countFileSize, (uint)countCmpSize, (uint)countFlag, 0,
            (uint)nameHash2, 0, (uint)nameHash2, (uint)nameHashSize, (uint)flagCount,
        ];
        for (int i = 0; i < fields.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), fields[i]);

        var flags = output.AsSpan(HeaderSize, flagCount * 4);
        for (int i = 0; i < flagCount; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(flags[(i * 4)..], flagArray[i]);

        var fileTable = output.AsSpan(HeaderSize + flagCount * 4, (int)fileTableSize);
        var nameHashes = output.AsSpan(HeaderSize + flagCount * 4 + (int)fileTableSize);
        for (int i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            long bit = (long)entrySize * i;
            MpqBitArray.SetBits(fileTable, bit, countFilePos, (ulong)entry.FilePosition);
            MpqBitArray.SetBits(fileTable, bit + indexFileSize, countFileSize, entry.FileSize);
            MpqBitArray.SetBits(fileTable, bit + indexCmpSize, countCmpSize, entry.CompressedSize);
            MpqBitArray.SetBits(fileTable, bit + indexFlag, countFlag, (ulong)FlagIndex(entry.Flags));
            MpqBitArray.SetBits(nameHashes, (long)nameHash2 * i, nameHash2, entry.NameHash);
        }
        return output;
    }
}
