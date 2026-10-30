using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// An MPQ archive. Several <see cref="MpqFileStream"/>s can be read concurrently; other members are not thread safe.
/// </summary>
public sealed partial class MpqArchive : IDisposable
{
    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly long _headerOffset;
    private readonly MpqFileTable _table;
    private volatile bool _disposed;

    private MpqArchive(Stream stream, bool leaveOpen, MpqHeader header, MpqUserData? userData, long headerOffset, MpqFileTable table, MpqOpenMode mode)
    {
        _stream = stream;
        _leaveOpen = leaveOpen;
        Header = header;
        UserData = userData;
        _headerOffset = headerOffset;
        _table = table;
        Mode = mode;
    }

    public MpqHeader Header { get; private set; }

    /// <summary>The "MPQ\x1B" user data block (StarCraft II replays and maps), or null.</summary>
    public MpqUserData? UserData { get; }

    public MpqOpenMode Mode { get; }

    /// <summary>Absolute position of the MPQ header in the stream.</summary>
    public long HeaderOffset => _headerOffset;

    /// <summary>Guards access to the underlying stream.</summary>
    internal object SyncRoot { get; } = new();

    /// <summary>Existing files, in block table order.</summary>
    public IEnumerable<MpqEntry> Entries
    {
        get
        {
            ThrowIfDisposed();
            return _table.Entries
                .Select((entry, index) => (entry, index))
                .Where(e => e.entry.Flags.HasFlag(MpqFileFlags.Exists))
                .Select(e => ToEntry(e.entry, e.index))
                .ToList();
        }
    }

    public static MpqArchive Open(string path, MpqOpenMode mode = MpqOpenMode.Read, MpqOpenOptions? options = null)
    {
        // StormLib opens archives with FILE_SHARE_READ in both modes (FileStream.cpp).
        var access = mode == MpqOpenMode.Read ? FileAccess.Read : FileAccess.ReadWrite;
        var stream = new FileStream(path, FileMode.Open, access, FileShare.Read);
        try
        {
            return Open(stream, mode, leaveOpen: false, options);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public static MpqArchive Open(Stream stream, MpqOpenMode mode = MpqOpenMode.Read, bool leaveOpen = false, MpqOpenOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
            throw new ArgumentException("The stream must be readable and seekable.", nameof(stream));
        if (mode == MpqOpenMode.ReadWrite && !stream.CanWrite)
            throw new ArgumentException("The stream must be writable for ReadWrite mode.", nameof(stream));

        options ??= MpqOpenOptions.Default;
        var (header, userData, headerOffset) = MpqHeaderReader.Find(stream, options.Strict);
        var table = MpqFileTable.Load(stream, header, headerOffset, options.Strict);
        var archive = new MpqArchive(stream, leaveOpen, header, userData, headerOffset, table, mode);
        archive.LoadInternalFiles(options);
        return archive;
    }

    /// <summary>
    /// Names files from <paramref name="fileNames"/> (StormLib SFileAddListFile); names already known are kept.
    /// The names appear in <see cref="Entries"/>.
    /// </summary>
    public void AddListFile(IEnumerable<string> fileNames)
    {
        ArgumentNullException.ThrowIfNull(fileNames);
        ThrowIfDisposed();
        foreach (string name in fileNames)
        {
            if (!string.IsNullOrEmpty(name))
                _table.AssignName(name);
        }
    }

    /// <summary>
    /// Applies the internal (listfile), the external list file and (attributes), like StormLib does when opening.
    /// Unreadable internal files are ignored unless <see cref="MpqOpenOptions.Strict"/> is set.
    /// </summary>
    private void LoadInternalFiles(MpqOpenOptions options)
    {
        foreach (string name in new[] { ListFile.ListFileName, ListFile.AttributesName, ListFile.SignatureName })
            _table.AssignName(name);

        // Internal files that exist are rewritten on Flush with their current flags (StormLib InvalidateInternalFile).
        _listFileFlags = FindExisting(ListFile.ListFileName)?.Flags;
        _attributesFileFlags = FindExisting(ListFile.AttributesName)?.Flags;

        byte[]? listFile = ReadInternalFile(ListFile.ListFileName, ListFile.MaxSize, options.Strict);
        if (listFile is not null)
            AddListFile(ListFile.Parse(listFile));
        if (options.ExternalListFile is not null)
            AddListFile(options.ExternalListFile);

        // StormLib sizes (attributes) by the header's block table size; without a block table it is not applied.
        int blockTableSize = (int)Math.Min(Header.BlockTableSize, (uint)_table.Entries.Count);
        byte[]? attributes = blockTableSize == 0
            ? null
            : ReadInternalFile(ListFile.AttributesName, MpqAttributes.MaxSize(blockTableSize), options.Strict);
        if (attributes is not null)
        {
            try
            {
                _attributeFlags = MpqAttributes.Apply(attributes, blockTableSize, _table.Entries) & ~MpqAttributeFlags.PatchBit;
            }
            catch (InvalidDataException) when (!options.Strict)
            {
                // StormLib ignores (attributes) it cannot parse.
            }
        }
    }

    /// <param name="maxSize">Files declaring a larger size are not read (StormLib CreateListFileCache limit).</param>
    private byte[]? ReadInternalFile(string name, long maxSize, bool strict)
    {
        if (FindExisting(name) is not { } entry)
            return null;
        if (entry.FileSize == 0 || entry.FileSize > maxSize)
            return strict ? throw new InvalidDataException($"Unexpected size of {name}.") : null;
        try
        {
            return CreateReader(name, entry.Clone()).ReadAll();
        }
        catch (Exception ex) when (!strict && ex is InvalidDataException or NotSupportedException or EndOfStreamException or InvalidOperationException)
        {
            return null;
        }
    }

    private MpqSectorReader CreateReader(string fileName, MpqFileEntry snapshot)
    {
        uint key = snapshot.Flags.HasFlag(MpqFileFlags.Encrypted)
            ? StormCrypto.GetFileKey(fileName, snapshot.FilePosition, snapshot.FileSize, snapshot.Flags.HasFlag(MpqFileFlags.FixKey))
            : 0;
        return new MpqSectorReader(_stream, _headerOffset, snapshot, Header.FormatVersion, Header.SectorSize, key);
    }

    /// <summary>Returns true when the file exists; '\' and '/' separators are interchangeable.</summary>
    public bool Contains(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ThrowIfDisposed();
        return FindExisting(fileName) is not null;
    }

    /// <summary>Opens a read-only, seekable stream over the uncompressed file data.</summary>
    /// <exception cref="FileNotFoundException">The file does not exist.</exception>
    public Stream OpenFile(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ThrowIfDisposed();

        var entry = FindExisting(fileName) ?? throw new FileNotFoundException($"'{fileName}' was not found in the archive.", fileName);
        return new MpqFileStream(this, CreateReader(fileName, entry.Clone()));
    }

    /// <summary>Writes pending changes (see <see cref="Flush"/>) and closes the archive.</summary>
    public void Dispose()
    {
        try
        {
            if (!_disposed && _dirty)
                Flush();
        }
        finally
        {
            // Wait for in-progress sector reads so the stream is never closed under them.
            lock (SyncRoot)
            {
                if (!_disposed)
                {
                    _disposed = true;
                    if (!_leaveOpen)
                        _stream.Dispose();
                }
            }
        }
    }

    internal bool IsDisposed => _disposed;

    internal void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    /// <summary>Patch files are only readable through a patch chain (StormLib behavior).</summary>
    private MpqFileEntry? FindExisting(string fileName) =>
        _table.Find(fileName) is { } entry
        && entry.Flags.HasFlag(MpqFileFlags.Exists)
        && !entry.Flags.HasFlag(MpqFileFlags.PatchFile)
            ? entry
            : null;

    private static MpqEntry ToEntry(MpqFileEntry entry, int index) => new()
    {
        Name = entry.FileName,
        BlockIndex = index,
        FileSize = entry.FileSize,
        CompressedSize = entry.CompressedSize,
        Flags = entry.Flags,
        Locale = entry.Locale,
    };
}
