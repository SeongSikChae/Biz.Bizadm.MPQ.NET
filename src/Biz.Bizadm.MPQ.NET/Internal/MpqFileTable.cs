namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Combined file table (StormLib TFileEntry array): one <see cref="MpqFileEntry"/> per block / BET entry, plus the
/// classic hash table and the HET table used for name lookup.
/// </summary>
internal sealed class MpqFileTable
{
    // StormLib BET_TABLE_MAX_SIZE: larger HET/BET tables are ignored.
    private const long ExtTableMaxSize = 0x00100000;

    private readonly MpqHashEntry[] _hash;
    private readonly MpqFileEntry[] _entries;
    private readonly HetTable? _het;

    public MpqFileTable(MpqHashEntry[] hash, MpqFileEntry[] entries, HetTable? het = null)
    {
        _hash = hash;
        _entries = entries;
        _het = het;

        // Copy the hash fields of the first slot that references each block.
        var assigned = new bool[entries.Length];
        foreach (var slot in hash)
        {
            uint index = slot.BlockIndex & MpqHashEntry.BlockIndexMask;
            if (slot.BlockIndex < MpqHashEntry.Deleted && index < entries.Length && !assigned[index])
            {
                var entry = entries[index];
                entry.HashA = slot.HashA;
                entry.HashB = slot.HashB;
                entry.Locale = slot.Locale;
                entry.Platform = slot.Platform;
                assigned[index] = true;
            }
        }
    }

    public IReadOnlyList<MpqFileEntry> Entries => _entries;

    public IReadOnlyList<MpqHashEntry> HashEntries => _hash;

    public HetTable? Het => _het;

    /// <summary>
    /// Reads the tables like StormLib LoadAnyHashTable + BuildFileTable: the HET table (v3+), the classic hash table,
    /// then the file table from the BET table and, when a hash table exists, from the block and hi-block tables.
    /// Tables may be compressed (v2+). In <paramref name="strict"/> mode v4 table MD5 mismatches throw.
    /// </summary>
    /// <param name="headerOffset">Absolute position of the MPQ header.</param>
    public static MpqFileTable Load(Stream stream, MpqHeader header, long headerOffset, bool strict = false)
    {
        var layout = MpqTableLayout.From(header, stream.Length, headerOffset);
        var v4 = header.V4;

        HetTable? het = null;
        if (header.HetTablePosition != 0 && layout.HetTableSize > 0 && layout.HetTableSize < ExtTableMaxSize)
        {
            byte[] hetData = MpqTableReader.LoadExtTable(stream, headerOffset + header.HetTablePosition, layout.HetTableSize,
                MpqTableReader.HetSignature, StormCrypto.HashTableKey, v4?.Md5HetTable ?? default, strict, "HET table");
            het = HetTable.Parse(hetData);
        }

        MpqHashEntry[] hash = [];
        if (header.HashTableSize != 0)
        {
            byte[] hashData = MpqTableReader.LoadTable(stream, headerOffset + header.HashTablePosition, layout.HashTableSize,
                header.HashTableSize * (long)HashTableSerializer.EntrySize, StormCrypto.HashTableKey,
                v4?.Md5HashTable ?? default, strict, "hash table");
            hash = HashTableSerializer.Parse(hashData);
        }

        // StormLib LoadAnyHashTable: an archive without hash and HET tables is an empty archive.
        if (het is null && hash.Length == 0)
            return new MpqFileTable([], []);

        byte[]? betData = null;
        uint betCount = 0;
        if (het is not null && header.BetTablePosition != 0 && layout.BetTableSize > 0 && layout.BetTableSize < ExtTableMaxSize)
        {
            betData = MpqTableReader.LoadExtTable(stream, headerOffset + header.BetTablePosition, layout.BetTableSize,
                MpqTableReader.BetSignature, StormCrypto.BlockTableKey, v4?.Md5BetTable ?? default, strict, "BET table");
            betCount = BetTable.ReadEntryCount(betData);
            // Every BET entry takes at least one bit, which bounds the allocation below.
            if (betCount > betData.LongLength * 8)
                throw new InvalidDataException("Invalid BET entry count.");
        }

        // Read the block table before allocating entries, so its size is bounded by the stream.
        byte[]? blockData = null;
        if (hash.Length != 0 && header.BlockTableSize != 0)
        {
            blockData = MpqTableReader.LoadTable(stream, headerOffset + header.BlockTablePosition, layout.BlockTableSize,
                header.BlockTableSize * (long)BlockTableSerializer.EntrySize, StormCrypto.BlockTableKey,
                v4?.Md5BlockTable ?? default, strict, "block table");
        }
        int blockCount = blockData is null ? 0 : blockData.Length / BlockTableSerializer.EntrySize;

        var entries = new MpqFileEntry[Math.Max(blockCount, (int)betCount)];
        for (int i = 0; i < entries.Length; i++)
            entries[i] = new MpqFileEntry();

        if (betData is not null)
            BetTable.Apply(betData, het!, entries);

        if (blockData is not null)
        {
            BlockTableSerializer.Parse(blockData, entries);
            if (header.FormatVersion >= MpqFormatVersion.Version2 && header.HiBlockTablePosition != 0)
                BlockTableSerializer.ApplyHiBlockTable(stream, headerOffset + header.HiBlockTablePosition, entries, blockCount,
                    v4?.Md5HiBlockTable ?? default, strict);
        }

        return new MpqFileTable(hash, entries, het);
    }

    /// <summary>
    /// Finds a file. Names are stored as given, so the name is tried as is, then with '/' replaced by '\',
    /// then with '\' replaced by '/'.
    /// </summary>
    public MpqFileEntry? Find(string name, ushort locale = 0, byte platform = 0) =>
        FindExact(name, locale, platform)
        ?? (name.Contains('/') ? FindExact(name.Replace('/', '\\'), locale, platform) : null)
        ?? (name.Contains('\\') ? FindExact(name.Replace('\\', '/'), locale, platform) : null);

    /// <summary>StormLib GetFileEntryLocale: the classic hash table first, then the HET table.</summary>
    private MpqFileEntry? FindExact(string name, ushort locale, byte platform) =>
        FindInHashTable(name, locale, platform) ?? FindInHet(name);

    private MpqFileEntry? FindInHet(string name) =>
        _het?.FindIndex(_het.HashName(name), _entries) is int index ? _entries[index] : null;

    /// <summary>
    /// StormLib GetFirstHashEntry/GetNextHashEntry/GetHashEntryLocale: an exact non-neutral locale and platform match wins
    /// immediately; otherwise the last slot whose locale and platform are neutral or matching.
    /// </summary>
    private MpqFileEntry? FindInHashTable(string name, ushort locale, byte platform)
    {
        if (_hash.Length == 0)
            return null;

        uint mask = (uint)_hash.Length - 1;
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & mask;
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        MpqFileEntry? best = null;

        uint i = start;
        do
        {
            ref readonly var slot = ref _hash[i];
            if (slot.BlockIndex == MpqHashEntry.Free)
                break;

            uint blockIndex = slot.BlockIndex & MpqHashEntry.BlockIndexMask;
            if (slot.HashA == a && slot.HashB == b && blockIndex < _entries.Length)
            {
                if ((locale != 0 || platform != 0) && slot.Locale == locale && slot.Platform == platform)
                    return _entries[blockIndex];
                if ((slot.Locale == 0 || slot.Locale == locale) && (slot.Platform == 0 || slot.Platform == platform))
                    best = _entries[blockIndex];
            }

            i = (i + 1) & mask;
        }
        while (i != start);

        return best;
    }
}
