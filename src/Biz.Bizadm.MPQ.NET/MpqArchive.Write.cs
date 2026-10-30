using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

public sealed partial class MpqArchive
{
    // StormLib MPQ_FILE_VALID_FLAGS_W3X: archives created as v1 do not get single-unit files.
    private const MpqFileFlags ValidFlagsV1Created = MpqFileFlags.Implode | MpqFileFlags.Compress | MpqFileFlags.Encrypted
        | MpqFileFlags.FixKey | MpqFileFlags.DeleteMarker | MpqFileFlags.SectorCrc | MpqFileFlags.Signature | MpqFileFlags.Exists;

    // StormLib MPQ_FILE_DEFAULT_INTERNAL: the flags are chosen from the file size when the internal file is first saved.
    private const MpqFileFlags DefaultInternalFlags = (MpqFileFlags)0xFFFFFFFF;

    private bool _dirty;
    private bool _created;
    private bool _internalFilesInvalidated;

    // Flags of (listfile) / (attributes) to write on Flush; null when the archive does not maintain them.
    private MpqFileFlags? _listFileFlags;
    private MpqFileFlags? _attributesFileFlags;
    private MpqAttributeFlags _attributeFlags = MpqAttributeFlags.Crc32 | MpqAttributeFlags.FileTime | MpqAttributeFlags.Md5;

    public static MpqArchive Create(string path, MpqArchiveCreateOptions? options = null)
    {
        var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
        try
        {
            return Create(stream, options, leaveOpen: false);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>Creates a new archive at the start of <paramref name="stream"/>; it is written on <see cref="Flush"/> or dispose.</summary>
    public static MpqArchive Create(Stream stream, MpqArchiveCreateOptions? options = null, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite || !stream.CanSeek)
            throw new ArgumentException("The stream must be readable, writable and seekable.", nameof(stream));
        options ??= MpqArchiveCreateOptions.Default;
        if (options.FormatVersion is not (MpqFormatVersion.Version1 or MpqFormatVersion.Version2))
            throw new NotSupportedException($"Creating {options.FormatVersion} archives is not supported yet.");
        if (options.HashTableSize < 4 || (options.HashTableSize & (options.HashTableSize - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(options), "HashTableSize must be a power of two of at least 4.");
        if (options.SectorSizeShift is < 0 or > 15)
            throw new ArgumentOutOfRangeException(nameof(options), "SectorSizeShift must be between 0 and 15.");

        uint headerSize = HeaderSize(options.FormatVersion);
        var header = new MpqHeader
        {
            HeaderSize = headerSize,
            FormatVersion = options.FormatVersion,
            SectorSizeShift = (ushort)options.SectorSizeShift,
            HashTablePosition = headerSize,
            BlockTablePosition = headerSize + options.HashTableSize * 16L,
            HashTableSize = (uint)options.HashTableSize,
            BlockTableSize = 0,
            ArchiveSize = headerSize + options.HashTableSize * 16L,
        };
        var hash = Enumerable.Repeat(new MpqHashEntry(MpqHashEntry.Free, MpqHashEntry.Free, 0xFFFF, 0xFF, 0xFF, MpqHashEntry.Free),
            options.HashTableSize).ToArray();

        return new MpqArchive(stream, leaveOpen, header, null, 0, new MpqFileTable(hash, []), MpqOpenMode.ReadWrite)
        {
            _created = true,
            _dirty = true,
            _listFileFlags = options.CreateListFile ? DefaultInternalFlags : null,
            _attributesFileFlags = options.CreateAttributes ? DefaultInternalFlags : null,
        };
    }

    /// <summary>
    /// Adds <paramref name="content"/> (read to its end) as <paramref name="fileName"/>. The name is stored as given.
    /// Changes are written by <see cref="Flush"/> or dispose.
    /// </summary>
    /// <exception cref="InvalidOperationException">The file exists and <see cref="MpqAddFileOptions.Overwrite"/> is false, or the hash table is full.</exception>
    public void AddFile(string fileName, Stream content, MpqAddFileOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        ArgumentNullException.ThrowIfNull(content);
        ThrowIfDisposed();
        EnsureWritable();
        if (ListFile.IsInternalName(fileName))
            throw new ArgumentException($"{fileName} is maintained by the archive.", nameof(fileName));

        options ??= MpqAddFileOptions.Default;
        using var buffer = new MemoryStream();
        content.CopyTo(buffer);
        if (buffer.Length > uint.MaxValue)
            throw new ArgumentException("Files larger than 4 GB are not supported.", nameof(content));

        var flags = MpqFileFlags.None;
        if (options.Compression != MpqCompressionType.None)
            flags |= MpqFileFlags.Compress;
        if (options.Encrypt)
            flags |= MpqFileFlags.Encrypted;
        if (options.FixKey)
            flags |= MpqFileFlags.FixKey;
        if (options.SingleUnit)
            flags |= MpqFileFlags.SingleUnit;
        if (options.SectorCrc)
            flags |= MpqFileFlags.SectorCrc;

        AddFileCore(fileName, buffer.ToArray(), flags, options.Compression, options.Locale, options.Overwrite, savingTables: false);
    }

    /// <summary>Writes (listfile), (attributes), the hash and block tables and the header.</summary>
    public void Flush()
    {
        ThrowIfDisposed();
        lock (SyncRoot)
        {
            if (!_dirty)
                return;

            // StormLib SFileFlushArchive: internal files are recreated after the file table is defragmented.
            InvalidateInternalFiles();
            _table.Defragment();
            if (_listFileFlags is { } listFileFlags)
            {
                byte[] listFile = ListFile.Serialize(_table.Entries
                    .Where(e => e.Flags.HasFlag(MpqFileFlags.Exists) && e.FileName is not null)
                    .Select(e => e.FileName!));
                // StormLib does not create an empty (listfile).
                if (listFile.Length != 0)
                {
                    _listFileFlags = listFileFlags = ResolveInternalFileFlags(listFileFlags, listFile.Length);
                    AddFileCore(ListFile.ListFileName, listFile, listFileFlags, MpqCompressionType.Zlib, 0, overwrite: true, savingTables: true);
                }
            }

            if (_attributesFileFlags is { } attributesFlags)
            {
                // The (attributes) entry itself is counted, with empty values (StormLib reserved entry).
                var entries = _table.Entries.Append(new MpqFileEntry()).ToList();
                byte[] attributes = MpqAttributes.Serialize(_attributeFlags, entries, entries.Count);
                _attributesFileFlags = attributesFlags = ResolveInternalFileFlags(attributesFlags, attributes.Length);
                AddFileCore(ListFile.AttributesName, attributes, attributesFlags, MpqCompressionType.Zlib, 0, overwrite: true, savingTables: true);
            }

            WriteTablesAndHeader();
            _dirty = false;
            _internalFilesInvalidated = false;
        }
    }

    private void EnsureWritable()
    {
        if (Mode != MpqOpenMode.ReadWrite)
            throw new InvalidOperationException("The archive is open for reading only.");
        if (Header.FormatVersion is not (MpqFormatVersion.Version1 or MpqFormatVersion.Version2))
            throw new NotSupportedException($"Writing {Header.FormatVersion} archives is not supported yet.");
        if (_table.Het is not null)
            throw new NotSupportedException("Writing archives with HET/BET tables is not supported yet.");
    }

    /// <summary>StormLib SFileAddFile_Init + SFileAddFile_Write + SFileAddFile_Finish for in-memory data.</summary>
    private void AddFileCore(string name, byte[] data, MpqFileFlags flags, MpqCompressionType compression, ushort locale,
        bool overwrite, bool savingTables)
    {
        flags = FilterFlags(flags);
        if (flags.HasFlag(MpqFileFlags.Compress))
            Compression.MpqCompression.ValidateMask(compression, Header.FormatVersion);

        lock (SyncRoot)
        {
            int slot = _table.FindSlotExact(name, locale);
            if (slot >= 0 && !overwrite)
                throw new InvalidOperationException($"'{name}' already exists in the archive.");

            long position = FindFreeSpace(includeInternalFiles: savingTables);
            if (Header.FormatVersion == MpqFormatVersion.Version1
                && position + data.Length + _table.HashTableSize * 16L + (_table.Entries.Count + 1) * 16L > uint.MaxValue)
                throw new IOException("A v1 archive cannot exceed 4 GB.");

            if (!savingTables)
                InvalidateInternalFiles();

            int blockIndex;
            if (slot >= 0)
            {
                blockIndex = (int)(_table.HashEntries[slot].BlockIndex & MpqHashEntry.BlockIndexMask);
            }
            else
            {
                // StormLib AllocateFileEntry: user files may not take the entries reserved for (listfile)/(attributes).
                int reserved = savingTables ? 0 : ReservedInternalFiles();
                slot = _table.FindFreeSlot(name, locale);
                if (slot < 0 || _table.HashTableSize - _table.ExistingCount <= reserved)
                    throw new InvalidOperationException("The hash table is full.");
                blockIndex = _table.AddEntry(new MpqFileEntry());
            }

            uint key = flags.HasFlag(MpqFileFlags.Encrypted)
                ? StormCrypto.GetFileKey(name, position, (uint)data.Length, flags.HasFlag(MpqFileFlags.FixKey))
                : 0;
            byte[] stored = MpqSectorWriter.Build(data, flags, compression, Header.SectorSize, key);
            _stream.Position = _headerOffset + position;
            _stream.Write(stored);

            var entry = _table.Entries[blockIndex];
            entry.FileName = name;
            entry.FilePosition = position;
            entry.FileSize = (uint)data.Length;
            entry.CompressedSize = (uint)stored.Length;
            entry.Flags = flags | MpqFileFlags.Exists;
            entry.Crc32 = Crc32.Compute(data);
            // StormLib finishes the MD5 only after writing data, so empty files keep a zero MD5.
            entry.Md5 = data.Length == 0 ? null : MD5.HashData(data);
            entry.FileTime = DateTime.UtcNow.ToFileTimeUtc();
            _table.SetSlot(slot, name, locale, blockIndex);
            _dirty = true;
        }
    }

    /// <summary>StormLib SFileCreateFile + SFileAddFile_Init flag rules.</summary>
    private MpqFileFlags FilterFlags(MpqFileFlags flags)
    {
        if (_created && Header.FormatVersion == MpqFormatVersion.Version1)
            flags &= ValidFlagsV1Created;
        if (flags.HasFlag(MpqFileFlags.SingleUnit))
            flags &= ~MpqFileFlags.SectorCrc;
        if ((flags & (MpqFileFlags.Compress | MpqFileFlags.Implode)) == 0)
            flags &= ~MpqFileFlags.SectorCrc;
        if (!flags.HasFlag(MpqFileFlags.Encrypted))
            flags &= ~MpqFileFlags.FixKey;
        if ((flags & (MpqFileFlags.Compress | MpqFileFlags.Implode)) == (MpqFileFlags.Compress | MpqFileFlags.Implode))
            throw new ArgumentException("Implode and Compress cannot be combined.");
        return flags & ~MpqFileFlags.Exists;
    }

    /// <summary>
    /// StormLib InvalidateInternalFiles: on the first change, (listfile) and (attributes) are deleted so that Flush
    /// writes them again after all other data.
    /// </summary>
    private void InvalidateInternalFiles()
    {
        if (_internalFilesInvalidated)
            return;
        _internalFilesInvalidated = true;

        foreach (string name in new[] { ListFile.ListFileName, ListFile.AttributesName })
        {
            int slot;
            while ((slot = _table.FindSlotExact(name, 0)) >= 0)
                _table.DeleteSlot(slot);
        }
    }

    /// <summary>Maintained internal files that are waiting to be written (StormLib dwReservedFiles).</summary>
    private int ReservedInternalFiles() =>
        (_listFileFlags is not null && FindExisting(ListFile.ListFileName) is null ? 1 : 0)
        + (_attributesFileFlags is not null && FindExisting(ListFile.AttributesName) is null ? 1 : 0);

    /// <summary>StormLib FindFreeMpqSpace:the end of the furthest existing file (internal files ignored unless saving).</summary>
    private long FindFreeSpace(bool includeInternalFiles)
    {
        long end = Header.HeaderSize;
        foreach (var entry in _table.Entries)
        {
            if (!entry.Flags.HasFlag(MpqFileFlags.Exists) || entry.CompressedSize == 0)
                continue;
            if (!includeInternalFiles && entry.FileName is not null && ListFile.IsInternalName(entry.FileName))
                continue;
            end = Math.Max(end, entry.FilePosition + entry.CompressedSize);
        }
        return end;
    }

    private void WriteTablesAndHeader()
    {
        long tablePosition = FindFreeSpace(includeInternalFiles: true);

        byte[] hash = HashTableSerializer.Serialize(_table.HashEntries);
        StormCrypto.EncryptBlock(hash.AsSpan(), StormCrypto.HashTableKey);
        byte[] block = BlockTableSerializer.Serialize(_table.Entries);
        StormCrypto.EncryptBlock(block.AsSpan(), StormCrypto.BlockTableKey);

        // StormLib TranslateBlockTable: the hi-block table is written only when a file starts above 4 GB.
        byte[]? hiBlock = null;
        if (_table.Entries.Any(e => e.FilePosition >> 32 != 0))
        {
            hiBlock = new byte[_table.Entries.Count * 2];
            for (int i = 0; i < _table.Entries.Count; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(hiBlock.AsSpan(i * 2), (ushort)(_table.Entries[i].FilePosition >> 32));
        }

        long blockPosition = tablePosition + hash.Length;
        long hiBlockPosition = hiBlock is null ? 0 : blockPosition + block.Length;
        long archiveSize = blockPosition + block.Length + (hiBlock?.Length ?? 0);
        uint headerSize = HeaderSize(Header.FormatVersion);
        Header = Header with
        {
            HeaderSize = headerSize,
            HashTablePosition = tablePosition,
            BlockTablePosition = blockPosition,
            BlockTableSize = (uint)_table.Entries.Count,
            HiBlockTablePosition = hiBlockPosition,
            ArchiveSize = archiveSize,
        };

        _stream.Position = _headerOffset + tablePosition;
        _stream.Write(hash);
        _stream.Write(block);
        if (hiBlock is not null)
            _stream.Write(hiBlock);

        Span<byte> header = stackalloc byte[(int)headerSize];
        BinaryPrimitives.WriteUInt32LittleEndian(header, MpqHeaderReader.HeaderSignature);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x04..], headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x08..], (uint)archiveSize);
        BinaryPrimitives.WriteUInt16LittleEndian(header[0x0C..], (ushort)Header.FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[0x0E..], Header.SectorSizeShift);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x10..], (uint)tablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x14..], (uint)blockPosition);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x18..], Header.HashTableSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x1C..], Header.BlockTableSize);
        if (Header.FormatVersion >= MpqFormatVersion.Version2)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x20..], (ulong)hiBlockPosition);
            BinaryPrimitives.WriteUInt16LittleEndian(header[0x28..], (ushort)(tablePosition >> 32));
            BinaryPrimitives.WriteUInt16LittleEndian(header[0x2A..], (ushort)(blockPosition >> 32));
        }
        _stream.Position = _headerOffset;
        _stream.Write(header);

        _stream.SetLength(_headerOffset + archiveSize);
        _stream.Flush();
    }

    private static uint HeaderSize(MpqFormatVersion version) =>
        (uint)(version == MpqFormatVersion.Version1 ? MpqHeaderReader.HeaderSizeV1 : MpqHeaderReader.HeaderSizeV2);

    private MpqFileFlags ResolveInternalFileFlags(MpqFileFlags flags, long fileSize) =>
        flags == DefaultInternalFlags ? DefaultInternalFileFlags(Header.FormatVersion, fileSize) : flags;

    /// <summary>StormLib GetDefaultSpecialFileFlags.</summary>
    private static MpqFileFlags DefaultInternalFileFlags(MpqFormatVersion version, long fileSize) =>
        version == MpqFormatVersion.Version1
            ? MpqFileFlags.Compress | MpqFileFlags.Encrypted | MpqFileFlags.FixKey
            : fileSize > 0x4000 ? MpqFileFlags.Compress | MpqFileFlags.SectorCrc : MpqFileFlags.Compress | MpqFileFlags.SingleUnit;
}
