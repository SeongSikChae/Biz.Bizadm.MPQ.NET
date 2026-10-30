namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Combined file table: one <see cref="MpqFileEntry"/> per block, plus the hash table slots used for name lookup.
/// </summary>
internal sealed class MpqFileTable
{
    private readonly MpqHashEntry[] _hash;
    private readonly MpqFileEntry[] _entries;

    public MpqFileTable(MpqHashEntry[] hash, MpqFileEntry[] entries)
    {
        _hash = hash;
        _entries = entries;

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

    /// <summary>Reads the hash and block tables. <paramref name="headerOffset"/> is the absolute position of the MPQ header.</summary>
    public static MpqFileTable Load(Stream stream, MpqHeader header, long headerOffset)
    {
        var hash = HashTableSerializer.Read(stream, headerOffset + header.HashTablePosition, header.HashTableSize);
        var entries = BlockTableSerializer.Read(stream, headerOffset + header.BlockTablePosition, header.BlockTableSize);
        return new MpqFileTable(hash, entries);
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
    /// StormLib GetFirstHashEntry/GetNextHashEntry/GetHashEntryLocale: an exact non-neutral locale and platform match wins
    /// immediately; otherwise the last slot whose locale and platform are neutral or matching.
    /// </summary>
    private MpqFileEntry? FindExact(string name, ushort locale, byte platform)
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
