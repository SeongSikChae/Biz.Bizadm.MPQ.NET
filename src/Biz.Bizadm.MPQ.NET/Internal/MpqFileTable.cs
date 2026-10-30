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
    private readonly List<MpqFileEntry> _entries;
    private readonly HetTable? _het;

    public MpqFileTable(MpqHashEntry[] hash, MpqFileEntry[] entries, HetTable? het = null)
    {
        _hash = hash;
        _entries = [.. entries];
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

    /// <summary>
    /// StormLib SListFileCreateNodeForAllLocales: names every existing entry that <paramref name="name"/> resolves to,
    /// in every locale, unless it already has a name.
    /// </summary>
    /// <returns>True when at least one entry was named.</returns>
    /// <remarks>
    /// With a HET table StormLib names the single entry GetFileEntryLocale returns; otherwise it scans the whole hash
    /// table for slots with the same name pair (also outside the probe chain). Separator variants of the name are tried
    /// like <see cref="Find"/>, and the variant that matched is stored as the name.
    /// </remarks>
    public bool AssignName(string name)
    {
        foreach (string candidate in NameCandidates(name))
        {
            IEnumerable<MpqFileEntry> matches = _het is not null
                ? FindExact(candidate, 0, 0) is { } entry ? [entry] : []
                : SlotsByName(candidate);

            bool found = false, assigned = false;
            foreach (var match in matches)
            {
                found = true;
                if (match.FileName is null)
                {
                    match.FileName = candidate;
                    assigned = true;
                }
            }
            if (found)
                return assigned;
        }
        return false;
    }

    private static IEnumerable<string> NameCandidates(string name)
    {
        yield return name;
        if (name.Contains('/'))
            yield return name.Replace('/', '\\');
        if (name.Contains('\\'))
            yield return name.Replace('\\', '/');
    }

    private Dictionary<(uint, uint), List<int>>? _slotsByName;

    /// <summary>Block indexes of every hash slot with the name pair of <paramref name="name"/> (StormLib linear scan).</summary>
    private IEnumerable<MpqFileEntry> SlotsByName(string name)
    {
        if (_slotsByName is null)
        {
            _slotsByName = [];
            foreach (var slot in _hash)
            {
                uint blockIndex = slot.BlockIndex & MpqHashEntry.BlockIndexMask;
                if (blockIndex >= _entries.Count)
                    continue;
                if (!_slotsByName.TryGetValue((slot.HashA, slot.HashB), out var list))
                    _slotsByName[(slot.HashA, slot.HashB)] = list = [];
                list.Add((int)blockIndex);
            }
        }

        var key = (StormCrypto.HashStringSlash(name, MpqHashType.NameA), StormCrypto.HashStringSlash(name, MpqHashType.NameB));
        return _slotsByName.TryGetValue(key, out var indexes) ? indexes.Select(i => _entries[i]) : [];
    }

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
            if (slot.HashA == a && slot.HashB == b && blockIndex < _entries.Count)
            {
                if ((locale != 0 || platform != 0) && slot.Locale == locale && slot.Platform == platform)
                    return _entries[(int)blockIndex];
                if ((slot.Locale == 0 || slot.Locale == locale) && (slot.Platform == 0 || slot.Platform == platform))
                    best = _entries[(int)blockIndex];
            }

            i = (i + 1) & mask;
        }
        while (i != start);

        return best;
    }

    // ---- Modification (classic hash table only; HET/BET archives are rewritten in a later unit) ----

    public int HashTableSize => _hash.Length;

    /// <summary>Hash slot of <paramref name="name"/> with exactly this locale and platform (StormLib GetHashEntryExact), or -1.</summary>
    public int FindSlotExact(string name, ushort locale, byte platform = 0)
    {
        int result = -1;
        ProbeChain(name, (index, slot) =>
        {
            uint blockIndex = slot.BlockIndex & MpqHashEntry.BlockIndexMask;
            if (blockIndex < _entries.Count && slot.Locale == locale && slot.Platform == platform)
                result = index; // StormLib keeps the last match
            return true;
        });
        return result;
    }

    /// <summary>
    /// StormLib FindFreeHashEntry: a slot with the same name pair and locale, else the first deleted slot,
    /// else the free slot that ends the chain; -1 when the table is full.
    /// </summary>
    public int FindFreeSlot(string name, ushort locale)
    {
        if (_hash.Length == 0)
            return -1;

        uint mask = (uint)_hash.Length - 1;
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & mask;
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        int deleted = -1;
        uint i = start;
        do
        {
            var slot = _hash[i];
            if (slot.HashA == a && slot.HashB == b && slot.Locale == locale)
                return (int)i;
            if (slot.BlockIndex == MpqHashEntry.Deleted && deleted < 0)
                deleted = (int)i;
            if (slot.BlockIndex == MpqHashEntry.Free)
                return deleted >= 0 ? deleted : (int)i;
            i = (i + 1) & mask;
        }
        while (i != start);
        return deleted;
    }

    /// <summary>StormLib AllocateFileEntry: reuses the first entry that does not exist, otherwise appends.</summary>
    public int AddEntry(MpqFileEntry entry)
    {
        _slotsByName = null;
        int free = _entries.FindIndex(e => !e.Flags.HasFlag(MpqFileFlags.Exists));
        if (free >= 0)
        {
            _entries[free] = entry;
            return free;
        }
        _entries.Add(entry);
        return _entries.Count - 1;
    }

    public int ExistingCount => _entries.Count(e => e.Flags.HasFlag(MpqFileFlags.Exists));

    /// <summary>
    /// StormLib DefragmentFileTable: removes entries that do not exist and remaps the hash table; slots of removed
    /// entries become "deleted".
    /// </summary>
    public void Defragment()
    {
        var map = new int[_entries.Count];
        var kept = new List<MpqFileEntry>(_entries.Count);
        for (int i = 0; i < _entries.Count; i++)
        {
            if (_entries[i].Flags.HasFlag(MpqFileFlags.Exists))
            {
                map[i] = kept.Count;
                kept.Add(_entries[i]);
            }
            else
            {
                map[i] = -1;
            }
        }
        if (kept.Count == _entries.Count)
            return;

        for (int i = 0; i < _hash.Length; i++)
        {
            var slot = _hash[i];
            uint blockIndex = slot.BlockIndex & MpqHashEntry.BlockIndexMask;
            if (blockIndex < _entries.Count)
                _hash[i] = slot with { BlockIndex = map[blockIndex] >= 0 ? (uint)map[blockIndex] : MpqHashEntry.Deleted };
        }
        _entries.Clear();
        _entries.AddRange(kept);
        _slotsByName = null;
    }

    /// <summary>Points hash slot <paramref name="slotIndex"/> at block <paramref name="blockIndex"/> for <paramref name="name"/>.</summary>
    public void SetSlot(int slotIndex, string name, ushort locale, int blockIndex)
    {
        var entry = _entries[blockIndex];
        entry.HashA = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        entry.HashB = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        entry.Locale = locale;
        entry.Platform = 0;
        _hash[slotIndex] = new MpqHashEntry(entry.HashA, entry.HashB, locale, 0, 0, (uint)blockIndex);
        _slotsByName = null;
    }

    /// <summary>
    /// StormLib DeleteFileEntry: the slot becomes "deleted"; the block keeps its position, sizes and other flags but
    /// loses MPQ_FILE_EXISTS and its name.
    /// </summary>
    public void DeleteSlot(int slotIndex)
    {
        uint blockIndex = _hash[slotIndex].BlockIndex & MpqHashEntry.BlockIndexMask;
        if (blockIndex < _entries.Count)
        {
            var entry = _entries[(int)blockIndex];
            entry.Flags &= ~MpqFileFlags.Exists;
            entry.FileName = null;
            entry.NameHash = 0;
        }
        _hash[slotIndex] = new MpqHashEntry(MpqHashEntry.Free, MpqHashEntry.Free, 0xFFFF, 0xFF, 0xFF, MpqHashEntry.Deleted);
        _slotsByName = null;
    }

    private void ProbeChain(string name, Func<int, MpqHashEntry, bool> visit)
    {
        if (_hash.Length == 0)
            return;
        uint mask = (uint)_hash.Length - 1;
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & mask;
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        uint i = start;
        do
        {
            var slot = _hash[i];
            if (slot.BlockIndex == MpqHashEntry.Free)
                return;
            if (slot.HashA == a && slot.HashB == b && !visit((int)i, slot))
                return;
            i = (i + 1) & mask;
        }
        while (i != start);
    }
}
