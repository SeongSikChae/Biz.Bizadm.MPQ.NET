using Biz.Bizadm.MPQ.NET.Internal;
using Biz.Bizadm.MPQ.NET.Internal.Patch;

namespace Biz.Bizadm.MPQ.NET;

public sealed partial class MpqArchive
{
    private const string PatchMetadataName = "(patch_metadata)";
    private const int MaxSc2PatchPrefix = 0x80;

    // StormLib FindArchiveLanguage: 4-character language groups and the WoW locale archive name templates.
    private const string LanguageList = "baseteenenUSenGBenCNenTWdeDEesESesMXfrFRitITkoKRptBRptPTruRUzhCNzhTW";
    private static readonly (string Template, int LanguageOffset)[] WowLocaleMpqs =
    [
        ("expansion1-locale-####", 18), ("expansion1-speech-####", 18),
        ("expansion2-locale-####", 18), ("expansion2-speech-####", 18),
        ("expansion3-locale-####", 18), ("expansion3-speech-####", 18),
        ("locale-####", 7), ("speech-####", 7),
    ];

    private readonly List<MpqArchive> _patchArchives = [];

    // Prefix of patched file names inside this archive when it is a patch archive, otherwise null.
    private string? _patchPrefix;

    /// <summary>Patch archives attached with <see cref="OpenPatchArchive"/>, in order.</summary>
    public IReadOnlyList<MpqArchive> PatchArchives => _patchArchives;

    /// <summary>
    /// Attaches a patch archive (StormLib SFileOpenPatchArchive). <see cref="OpenFile"/> then returns files with all
    /// patches of the chain applied. The archive must be open for reading only.
    /// </summary>
    /// <param name="path">Path of the patch archive to open.</param>
    /// <param name="prefix">
    /// Folder of the patched files inside the patch archive. When null it is detected like StormLib does
    /// (World of Warcraft locale and base prefixes, StarCraft II archive placement); otherwise no prefix.
    /// </param>
    /// <exception cref="InvalidOperationException">The archive is writable, or the patch prefix cannot be found.</exception>
    public void OpenPatchArchive(string path, string? prefix = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ThrowIfDisposed();
        // StormLib does not patch archives open for writing: changed files could not be combined with patches.
        if (Mode != MpqOpenMode.Read)
            throw new InvalidOperationException("Patch archives can only be added to archives open for reading.");

        var patch = Open(path, MpqOpenMode.Read, new MpqOpenOptions { MaxBufferSize = _maxBufferSize });
        try
        {
            patch._patchPrefix = FindPatchPrefix(patch, prefix)
                ?? throw new InvalidOperationException("The patch prefix of the archive cannot be found.");
            _patchArchives.Add(patch);
        }
        catch
        {
            patch.Dispose();
            throw;
        }
    }

    /// <summary>A file in a patch chain: its base version and the patch files on top of it.</summary>
    private sealed record PatchedFile(MpqArchive BaseArchive, MpqFileEntry BaseEntry, IReadOnlyList<(MpqArchive Archive, MpqFileEntry Entry)> Patches);

    /// <summary>
    /// StormLib OpenPatchedFile: the base version is the last non-patch file in the chain (this archive, then the patch
    /// archives); the files with the same name after it are its patches.
    /// </summary>
    /// <returns>Null when the file is not in the chain, or its newest version has the delete marker.</returns>
    private PatchedFile? ResolvePatched(string fileName)
    {
        var chain = new List<MpqArchive> { this };
        chain.AddRange(_patchArchives);

        int baseIndex = -1;
        for (int i = 0; i < chain.Count; i++)
        {
            if (chain[i].FindInChain(fileName) is { } entry && !entry.Flags.HasFlag(MpqFileFlags.PatchFile))
                baseIndex = i;
        }
        if (baseIndex < 0)
            return null;

        var baseEntry = chain[baseIndex].FindInChain(fileName)!;
        var patches = new List<(MpqArchive Archive, MpqFileEntry Entry)>();
        for (int i = baseIndex + 1; i < chain.Count; i++)
        {
            if (chain[i].FindInChain(fileName) is { } entry)
                patches.Add((chain[i], entry));
        }

        var newest = patches.Count > 0 ? patches[^1].Entry : baseEntry;
        return newest.Flags.HasFlag(MpqFileFlags.DeleteMarker) ? null : new PatchedFile(chain[baseIndex], baseEntry, patches);
    }

    /// <summary>Opens a file of a patch chain: unpatched files are streamed, patched ones are applied in memory.</summary>
    private Stream OpenPatched(string fileName, PatchedFile file)
    {
        if (file.Patches.Count == 0)
            return file.BaseArchive.OpenEntry(file.BaseArchive.ChainFileName(fileName), file.BaseEntry);

        byte[] data = file.BaseArchive.ReadAllInChain(fileName, file.BaseEntry);
        var patchFiles = file.Patches.Select(p => p.Archive.ReadAllInChain(fileName, p.Entry)).ToList();
        uint maxFileSize = file.Patches.Select(p => p.Entry.FileSize).Append(file.BaseEntry.FileSize).Max();
        byte[] patched = MpqPatch.ApplyChain(data, file.BaseEntry.Md5, patchFiles, maxFileSize, _maxBufferSize);
        return new MemoryStream(patched, writable: false);
    }

    /// <summary>StormLib GetPatchFileName + GetFileEntryExact: the existing entry of a chain member, in the neutral locale.</summary>
    private MpqFileEntry? FindInChain(string fileName)
    {
        string name = ChainFileName(fileName);
        return _table.Find(name) is { } entry && entry.Flags.HasFlag(MpqFileFlags.Exists) ? entry : null;
    }

    /// <summary>
    /// StormLib GetPatchFileName: patch archives prepend their prefix and drop a leading "OldWorld\" ('/' accepted too,
    /// like every lookup here).
    /// </summary>
    private string ChainFileName(string fileName)
    {
        if (_patchPrefix is null)
            return fileName;
        if (fileName.StartsWith(@"OldWorld\", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith("OldWorld/", StringComparison.OrdinalIgnoreCase))
            fileName = fileName[9..];
        return _patchPrefix + fileName;
    }

    private byte[] ReadAllInChain(string fileName, MpqFileEntry entry)
    {
        lock (SyncRoot)
        {
            ThrowIfDisposed();
            return CreateReader(ChainFileName(fileName), entry.Clone()).ReadAll();
        }
    }

    /// <summary>
    /// StormLib FindPatchPrefix, for <paramref name="patch"/> attached to this (base) archive.
    /// </summary>
    /// <returns>The prefix ("" or ending with '\'), or null when it cannot be found.</returns>
    private string? FindPatchPrefix(MpqArchive patch, string? prefix)
    {
        if (prefix is not null)
            return CreatePatchPrefix(prefix);

        // World of Warcraft: patches with prefixes have "base\(patch_metadata)".
        if (patch.FindNeutral(@"base\" + PatchMetadataName) is not null)
            return FindArchiveLanguage() + @"\";

        // StarCraft II: every base archive has "StreamingBuckets.txt".
        if (FindNeutral("StreamingBuckets.txt") is { } streamingBuckets)
            return FindPatchPrefixSc2ArchiveName(patch) ?? FindPatchPrefixSc2HelperFile(patch) ?? FindPatchPrefixSc2MatchFiles(patch, streamingBuckets);

        // Diablo III and Hearthstone patches have no prefix.
        return "";
    }

    /// <summary>StormLib CreatePatchPrefix: a non-empty prefix ends with a backslash.</summary>
    private static string CreatePatchPrefix(string prefix) =>
        prefix.Length == 0 || prefix.EndsWith('\\') ? prefix : prefix + @"\";

    /// <summary>StormLib CheckAndCreatePatchPrefix: the prefix is used when "&lt;prefix&gt;\(patch_metadata)" exists.</summary>
    private static string? CheckPatchPrefix(MpqArchive patch, string prefix) =>
        prefix.Length <= MaxSc2PatchPrefix && patch.FindNeutral(prefix + @"\" + PatchMetadataName) is not null
            ? CreatePatchPrefix(prefix)
            : null;

    /// <summary>StormLib FindArchiveLanguage: the language of "&lt;template&gt;-md5.lst" in this archive, or "Base".</summary>
    private string FindArchiveLanguage()
    {
        foreach (var (template, offset) in WowLocaleMpqs)
        {
            for (int i = 0; i < LanguageList.Length; i += 4)
            {
                string language = LanguageList.Substring(i, 4);
                string name = template[..offset] + language + template[(offset + 4)..] + "-md5.lst";
                if (FindNeutral(name) is not null)
                    return language;
            }
        }
        return "Base";
    }

    /// <summary>
    /// StormLib FindPatchPrefix_SC2_ArchiveName: the part of the base archive path from "Battle.net", "Campaigns" or
    /// "Mods" ('/' and '#' read as '\').
    /// </summary>
    private string? FindPatchPrefixSc2ArchiveName(MpqArchive patch)
    {
        if (_path is null)
            return null;
        string path = _path;
        int begin = Math.Max(0, path.Length - MaxSc2PatchPrefix);
        int end = path.Length;
        char At(int index) => index < path.Length ? path[index] : '\0';

        int dots = 0, slashes = 0, separator = -1;
        int ptr;
        for (ptr = end; ptr > begin; ptr--)
        {
            if (At(ptr) == '.')
            {
                dots++;
                break;
            }
        }

        for (; ptr > begin; ptr--)
        {
            if (At(ptr) is '\\' or '/' or '#')
            {
                if (dots == 0)
                    return null;
                separator = ptr;
                slashes++;
            }

            if (separator >= 0 && slashes >= dots)
            {
                foreach (string expected in new[] { "Battle.net", "Campaigns", "Mods" })
                {
                    if (separator - ptr == expected.Length && string.Compare(path, ptr, expected, 0, expected.Length, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        string prefix = path[ptr..end].Replace('/', '\\').Replace('#', '\\');
                        if (CheckPatchPrefix(patch, prefix) is { } found)
                            return found;
                    }
                }
            }
        }
        return null;
    }

    /// <summary>StormLib FindPatchPrefix_SC2_HelperFile: "PatchPrefix=..." in "&lt;base archive path&gt;-PATCH".</summary>
    private string? FindPatchPrefixSc2HelperFile(MpqArchive patch)
    {
        string? helper = _path is null ? null : _path + "-PATCH";
        if (helper is null || !File.Exists(helper))
            return null;
        // The size is checked before reading (StormLib reads at most MAX_PATH bytes).
        byte[] data;
        using (var file = new FileStream(helper, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length is < 12 or >= 260)
                return null;
            data = new byte[file.Length];
            file.ReadExactly(data);
        }

        string text = System.Text.Encoding.Latin1.GetString(data);
        if (!text.StartsWith("PatchPrefix", StringComparison.OrdinalIgnoreCase))
            return null;
        int start = 11;
        while (start < text.Length && text[start] is ' ' or '=')
            start++;
        int stop = start;
        while (stop < text.Length && text[stop] is not ('\0' or '\n' or '\r'))
            stop++;
        return stop > start && stop - start <= MaxSc2PatchPrefix ? CheckPatchPrefix(patch, text[start..stop]) : null;
    }

    /// <summary>
    /// StormLib FindPatchPrefix_SC2_MatchFiles: for the first patch, the folder of a "(patch_metadata)" whose
    /// "StreamingBuckets.txt" patches the base version (md5_before_patch); later patches reuse the first prefix.
    /// </summary>
    private string? FindPatchPrefixSc2MatchFiles(MpqArchive patch, MpqFileEntry streamingBuckets)
    {
        if (_patchArchives.Count > 0)
            return _patchArchives[0]._patchPrefix;

        byte[] baseMd5 = streamingBuckets.Md5 ?? new byte[16];
        foreach (var entry in patch._table.Entries)
        {
            // StormLib IsPatchMetadataFile
            if (entry.FileName is not { } name || entry.Flags.HasFlag(MpqFileFlags.PatchFile)
                || entry.FileSize is 0 or >= 0x40 || !Path.GetFileName(name.Replace('\\', '/')).Equals(PatchMetadataName, StringComparison.OrdinalIgnoreCase))
                continue;

            int plain = name.LastIndexOfAny(['\\', '/']) + 1;
            string candidate = name[..plain] + streamingBuckets.FileName;
            if (patch.IsMatchingPatchFile(candidate, baseMd5))
                return CreatePatchPrefix(name[..plain]);
        }
        return null;
    }

    /// <summary>StormLib IsMatchingPatchFile: a patch file whose md5_before_patch is <paramref name="baseMd5"/>.</summary>
    private bool IsMatchingPatchFile(string fileName, byte[] baseMd5)
    {
        if (_table.Find(fileName) is not { } entry || !entry.Flags.HasFlag(MpqFileFlags.Exists) || !entry.Flags.HasFlag(MpqFileFlags.PatchFile))
            return false;
        try
        {
            // Only the patch header is read, like StormLib.
            var header = new byte[MpqPatch.HeaderSize];
            int read = 0;
            lock (SyncRoot)
            {
                var reader = CreateReader(fileName, entry.Clone());
                var sector = new byte[reader.SectorSize];
                for (int i = 0; i < reader.SectorCount && read < header.Length; i++)
                {
                    int length = reader.ReadSector(i, sector);
                    int count = Math.Min(length, header.Length - read);
                    sector.AsSpan(0, count).CopyTo(header.AsSpan(read));
                    read += count;
                }
            }
            return read == header.Length && BitConverter.ToUInt32(header) == 0x48435450
                && MpqPatch.Header.Read(header).Md5Before.AsSpan().SequenceEqual(baseMd5);
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or EndOfStreamException or InvalidOperationException)
        {
            // StormLib: a patch file that cannot be opened or read does not match.
            return false;
        }
    }

    /// <summary>StormLib GetFileEntryLocale(..., 0): an existing entry, patch files included.</summary>
    private MpqFileEntry? FindNeutral(string fileName) =>
        _table.Find(fileName) is { } entry && entry.Flags.HasFlag(MpqFileFlags.Exists) ? entry : null;
}
