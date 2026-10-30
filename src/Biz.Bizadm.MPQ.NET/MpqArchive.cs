using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// An MPQ archive. Several <see cref="MpqFileStream"/>s can be read concurrently; other members are not thread safe.
/// </summary>
public sealed class MpqArchive : IDisposable
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

    public MpqHeader Header { get; }

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

        var (header, userData, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);
        return new MpqArchive(stream, leaveOpen, header, userData, headerOffset, table, mode);
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
        var snapshot = entry.Clone();
        uint key = snapshot.Flags.HasFlag(MpqFileFlags.Encrypted)
            ? StormCrypto.GetFileKey(fileName, snapshot.FilePosition, snapshot.FileSize, snapshot.Flags.HasFlag(MpqFileFlags.FixKey))
            : 0;
        var reader = new MpqSectorReader(_stream, _headerOffset, snapshot, Header.FormatVersion, Header.SectorSize, key);
        return new MpqFileStream(this, reader);
    }

    public void Dispose()
    {
        // Wait for in-progress sector reads so the stream is never closed under them.
        lock (SyncRoot)
        {
            if (_disposed)
                return;
            _disposed = true;
            if (!_leaveOpen)
                _stream.Dispose();
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
