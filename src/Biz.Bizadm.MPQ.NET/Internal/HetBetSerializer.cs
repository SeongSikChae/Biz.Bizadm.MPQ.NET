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
}
