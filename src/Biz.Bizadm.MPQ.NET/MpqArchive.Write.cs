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
    // Non-null when the archive has a weak signature that Flush recreates and signs (StormLib dwFileFlags3).
    private MpqFileFlags? _signatureFlags;
    private MpqAttributeFlags _attributeFlags = MpqAttributeFlags.Crc32 | MpqAttributeFlags.FileTime | MpqAttributeFlags.Md5;

    public static MpqArchive Create(string path, MpqArchiveCreateOptions? options = null)
    {
        var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
        try
        {
            var archive = Create(stream, options, leaveOpen: false);
            archive._path = Path.GetFullPath(path);
            return archive;
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
        if (options.FormatVersion is < MpqFormatVersion.Version1 or > MpqFormatVersion.Version4)
            throw new ArgumentOutOfRangeException(nameof(options), "Unknown format version.");
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
            // StormLib SFileCreateArchive: v4 archives store the MD5 of every 0x4000-byte raw data chunk.
            V4 = options.FormatVersion == MpqFormatVersion.Version4 ? EmptyHeaderV4(rawChunkSize: 0x4000) : null,
        };
        var hash = Enumerable.Repeat(new MpqHashEntry(MpqHashEntry.Free, MpqHashEntry.Free, 0xFFFF, 0xFF, 0xFF, MpqHashEntry.Free),
            options.HashTableSize).ToArray();

        // StormLib SFileCreateArchive2: v3+ archives get a HET table; SFileCreateArchive adds patch bits to (attributes).
        bool v3 = options.FormatVersion >= MpqFormatVersion.Version3;
        var table = new MpqFileTable(hash, [], v3 ? HetTable.Build([]) : null);
        return new MpqArchive(stream, leaveOpen, header, null, 0, table, MpqOpenMode.ReadWrite)
        {
            _created = true,
            _dirty = true,
            _listFileFlags = options.CreateListFile ? DefaultInternalFlags : null,
            _attributesFileFlags = options.CreateAttributes ? DefaultInternalFlags : null,
            _attributeFlags = MpqAttributeFlags.Crc32 | MpqAttributeFlags.FileTime | MpqAttributeFlags.Md5
                | (v3 ? MpqAttributeFlags.PatchBit : 0),
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

            // StormLib SSignFileCreate: a zeroed (signature) that is signed after the tables are written.
            // StormLib expects its flags to be MPQ_FILE_EXISTS only: not compressed and not encrypted.
            if (_signatureFlags is not null)
            {
                AddFileCore(ListFile.SignatureName, new byte[MpqSignature.FileSize], MpqFileFlags.None, MpqCompressionType.None, 0,
                    overwrite: true, savingTables: true);
                // The CRC is cleared because the content changes when the archive is signed.
                _table.Find(ListFile.SignatureName)!.Crc32 = 0;
            }

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

            _table.RebuildHet();
            WriteTablesAndHeader();
            if (_signatureFlags is not null)
                FinishWeakSignature();
            _dirty = false;
            _internalFilesInvalidated = false;
        }
    }

    private void EnsureWritable()
    {
        if (Mode != MpqOpenMode.ReadWrite)
            throw new InvalidOperationException("The archive is open for reading only.");
        if (_malformed)
            throw new InvalidOperationException("The archive is malformed and was repaired when opened; it cannot be modified.");
    }

    /// <summary>Size of the raw data chunks whose MD5s follow file data and HET/BET tables (v4), or 0.</summary>
    private uint RawChunkSize => Header.V4?.RawChunkSize ?? 0;

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
            EnsureV1Size(position, data.Length);

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
            byte[] stored = MpqSectorWriter.Build(data, flags, compression, Header.SectorSize, key, emptySectorCrc: RawChunkSize != 0);
            _stream.Position = _headerOffset + position;
            _stream.Write(stored);
            // StormLib SFileAddFile_Finish (WriteMpqDataMD5); nothing is stored for empty files.
            if (RawChunkSize != 0 && stored.Length != 0)
                _stream.Write(ChunkMd5s(stored, RawChunkSize));

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
            // StormLib AllocateFileEntry / SFileAddFile_Finish: name hash for the HET table, which is then rebuilt.
            if (_table.Het is { } het)
                entry.NameHash = het.HashName(name);
            _table.SetSlot(slot, name, locale, blockIndex);
            _table.RebuildHet();
            _dirty = true;
        }
    }

    /// <summary>A v1 archive, with its tables and one more block entry, must stay below 4 GB.</summary>
    private void EnsureV1Size(long position, long length)
    {
        if (Header.FormatVersion == MpqFormatVersion.Version1
            && position + length + _table.HashTableSize * 16L + (_table.Entries.Count + 1) * 16L > uint.MaxValue)
            throw new IOException("A v1 archive cannot exceed 4 GB.");
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

        foreach (string name in new[] { ListFile.ListFileName, ListFile.AttributesName, ListFile.SignatureName })
        {
            int slot;
            while ((slot = _table.FindSlotExact(name, 0)) >= 0)
                _table.DeleteSlot(slot);
        }
    }

    /// <summary>Maintained internal files that are waiting to be written (StormLib dwReservedFiles).</summary>
    private int ReservedInternalFiles() =>
        (_listFileFlags is not null && FindExisting(ListFile.ListFileName) is null ? 1 : 0)
        + (_attributesFileFlags is not null && FindExisting(ListFile.AttributesName) is null ? 1 : 0)
        + (_signatureFlags is not null && FindExisting(ListFile.SignatureName) is null ? 1 : 0);

    /// <summary>
    /// StormLib FindFreeMpqSpace: the end of the furthest existing file, including its raw chunk MD5s (internal files
    /// ignored unless saving).
    /// </summary>
    private long FindFreeSpace(bool includeInternalFiles)
    {
        long end = Header.HeaderSize;
        foreach (var entry in _table.Entries)
        {
            if (!entry.Flags.HasFlag(MpqFileFlags.Exists) || entry.CompressedSize == 0)
                continue;
            if (!includeInternalFiles && entry.FileName is not null && ListFile.IsInternalName(entry.FileName))
                continue;
            // StormLib compares the end of the data with the current end, which already includes MD5s.
            if (entry.FilePosition + entry.CompressedSize > end)
                end = DataEnd(entry);
        }
        // Data of deleted or replaced files that open streams still read is not overwritten.
        return Math.Max(end, _openStreamDataEnd);
    }

    /// <summary>End of the stored data of <paramref name="entry"/>, including its raw chunk MD5s (v4).</summary>
    private long DataEnd(MpqFileEntry entry) =>
        entry.FilePosition + entry.CompressedSize + RawChunkMd5Size(entry.CompressedSize);

    private void WriteTablesAndHeader()
    {
        long position = FindFreeSpace(includeInternalFiles: true);

        // StormLib SaveMPQTables: HET, BET, hash, block and hi-block tables in this order.
        long hetPosition = 0, betPosition = 0;
        byte[] hetTable = [], betTable = [];
        if (_table.Het is { } het)
        {
            hetTable = ExtTable(MpqTableReader.HetSignature, het.Serialize(), StormCrypto.HashTableKey);
            betTable = ExtTable(MpqTableReader.BetSignature, BetTable.Serialize(_table.Entries, het), StormCrypto.BlockTableKey);
            // StormLib SaveExtTable: raw chunk MD5s follow each table (WriteMemDataMD5).
            hetPosition = position;
            betPosition = hetPosition + hetTable.Length + RawChunkMd5Size(hetTable.Length);
            _stream.Position = _headerOffset + hetPosition;
            WriteWithChunkMd5s(hetTable);
            WriteWithChunkMd5s(betTable);
            position = betPosition + betTable.Length + RawChunkMd5Size(betTable.Length);
        }
        long tablePosition = position;

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
        // StormLib SaveMPQTables: MD5s of the stored tables; the hi-block table MD5 is not calculated (zero = not checked).
        MpqHeaderV4? v4 = Header.FormatVersion == MpqFormatVersion.Version4
            ? EmptyHeaderV4(RawChunkSize) with
            {
                HashTableSize64 = hash.Length,
                BlockTableSize64 = block.Length,
                HiBlockTableSize64 = hiBlock?.Length ?? 0,
                HetTableSize64 = hetTable.Length,
                BetTableSize64 = betTable.Length,
                Md5HashTable = MD5.HashData(hash),
                Md5BlockTable = MD5.HashData(block),
                Md5HetTable = hetTable.Length == 0 ? new byte[16] : MD5.HashData(hetTable),
                Md5BetTable = betTable.Length == 0 ? new byte[16] : MD5.HashData(betTable),
            }
            : null;
        Header = Header with
        {
            HeaderSize = headerSize,
            HashTablePosition = tablePosition,
            BlockTablePosition = blockPosition,
            BlockTableSize = (uint)_table.Entries.Count,
            HiBlockTablePosition = hiBlockPosition,
            HetTablePosition = hetPosition,
            BetTablePosition = betPosition,
            ArchiveSize = archiveSize,
            V4 = v4,
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
        if (Header.FormatVersion >= MpqFormatVersion.Version3)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x2C..], (ulong)archiveSize);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x34..], (ulong)betPosition);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x3C..], (ulong)hetPosition);
        }
        if (v4 is not null)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x44..], (ulong)v4.HashTableSize64);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x4C..], (ulong)v4.BlockTableSize64);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x54..], (ulong)v4.HiBlockTableSize64);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x5C..], (ulong)v4.HetTableSize64);
            BinaryPrimitives.WriteUInt64LittleEndian(header[0x64..], (ulong)v4.BetTableSize64);
            BinaryPrimitives.WriteUInt32LittleEndian(header[0x6C..], v4.RawChunkSize);
            v4.Md5BlockTable.Span.CopyTo(header[0x70..]);
            v4.Md5HashTable.Span.CopyTo(header[0x80..]);
            v4.Md5HiBlockTable.Span.CopyTo(header[0x90..]);
            v4.Md5BetTable.Span.CopyTo(header[0xA0..]);
            v4.Md5HetTable.Span.CopyTo(header[0xB0..]);
            byte[] headerMd5 = MD5.HashData(header[..0xC0]);
            headerMd5.CopyTo(header[0xC0..]);
            Header = Header with { V4 = v4 with { Md5MpqHeader = headerMd5 } };
        }
        _stream.Position = _headerOffset;
        _stream.Write(header);

        _stream.SetLength(_headerOffset + archiveSize);
        _stream.Flush();
    }

    private static uint HeaderSize(MpqFormatVersion version) => (uint)(version switch
    {
        MpqFormatVersion.Version1 => MpqHeaderReader.HeaderSizeV1,
        MpqFormatVersion.Version2 => MpqHeaderReader.HeaderSizeV2,
        MpqFormatVersion.Version3 => MpqHeaderReader.HeaderSizeV3,
        _ => MpqHeaderReader.HeaderSizeV4,
    });

    private static MpqHeaderV4 EmptyHeaderV4(uint rawChunkSize) => new()
    {
        HashTableSize64 = 0,
        BlockTableSize64 = 0,
        HiBlockTableSize64 = 0,
        HetTableSize64 = 0,
        BetTableSize64 = 0,
        RawChunkSize = rawChunkSize,
        Md5BlockTable = new byte[16],
        Md5HashTable = new byte[16],
        Md5HiBlockTable = new byte[16],
        Md5BetTable = new byte[16],
        Md5HetTable = new byte[16],
        Md5MpqHeader = new byte[16],
    };

    private long RawChunkMd5Size(long dataSize) =>
        RawChunkSize == 0 || dataSize == 0 ? 0 : ((dataSize - 1) / RawChunkSize + 1) * MD5.HashSizeInBytes;

    /// <summary>StormLib WriteMemDataMD5: the MD5 of every <paramref name="chunkSize"/>-byte chunk of <paramref name="data"/>.</summary>
    private static byte[] ChunkMd5s(ReadOnlySpan<byte> data, uint chunkSize)
    {
        var output = new byte[((data.Length - 1) / chunkSize + 1) * MD5.HashSizeInBytes];
        for (int i = 0, offset = 0; offset < data.Length; i++, offset += (int)chunkSize)
            MD5.HashData(data.Slice(offset, (int)Math.Min(chunkSize, data.Length - offset)), output.AsSpan(i * MD5.HashSizeInBytes));
        return output;
    }

    /// <summary>Writes <paramref name="data"/> at the current position, followed by its raw chunk MD5s (v4).</summary>
    private void WriteWithChunkMd5s(byte[] data)
    {
        _stream.Write(data);
        if (RawChunkSize != 0)
            _stream.Write(ChunkMd5s(data, RawChunkSize));
    }

    /// <summary>StormLib SaveExtTable without compression: the extended header and the encrypted table.</summary>
    private static byte[] ExtTable(uint signature, byte[] table, uint key)
    {
        var output = new byte[12 + table.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(output, signature);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8), (uint)table.Length);
        table.CopyTo(output, 12);
        StormCrypto.EncryptBlock(output.AsSpan(12), key);
        return output;
    }

    private MpqFileFlags ResolveInternalFileFlags(MpqFileFlags flags, long fileSize) =>
        flags == DefaultInternalFlags ? DefaultInternalFileFlags(Header.FormatVersion, fileSize) : flags;

    /// <summary>StormLib GetDefaultSpecialFileFlags.</summary>
    private static MpqFileFlags DefaultInternalFileFlags(MpqFormatVersion version, long fileSize) =>
        version == MpqFormatVersion.Version1
            ? MpqFileFlags.Compress | MpqFileFlags.Encrypted | MpqFileFlags.FixKey
            : fileSize > 0x4000 ? MpqFileFlags.Compress | MpqFileFlags.SectorCrc : MpqFileFlags.Compress | MpqFileFlags.SingleUnit;
}
