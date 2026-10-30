using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

public sealed partial class MpqArchive
{
    /// <summary>
    /// Deletes a file (StormLib SFileRemoveFile). Its data stays in the archive until <see cref="Compact"/>;
    /// streams already open on it keep reading. The change is written by <see cref="Flush"/> or dispose.
    /// </summary>
    /// <exception cref="FileNotFoundException">The file does not exist.</exception>
    public void DeleteFile(string fileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        ThrowIfDisposed();
        EnsureWritable();
        if (ListFile.IsInternalName(fileName))
            throw new ArgumentException($"{fileName} is maintained by the archive.", nameof(fileName));

        lock (SyncRoot)
        {
            int slot = FindModifiableSlot(fileName);
            _table.DeleteSlot(slot);
            InvalidateInternalFiles();
            _dirty = true;
        }
    }

    /// <summary>
    /// Renames a file, keeping its locale (StormLib SFileRenameFile). When the encryption key changes, the data is
    /// re-encrypted into a new copy at the end of the archive, so streams already open keep reading the old copy.
    /// The change is written by <see cref="Flush"/> or dispose.
    /// </summary>
    /// <exception cref="FileNotFoundException">The file does not exist.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="newName"/> already exists in the same locale.</exception>
    public void RenameFile(string fileName, string newName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        ArgumentException.ThrowIfNullOrEmpty(newName);
        ThrowIfDisposed();
        EnsureWritable();
        if (ListFile.IsInternalName(fileName) || ListFile.IsInternalName(newName))
            throw new ArgumentException("Internal files cannot be renamed.");
        ListFile.ValidateNewName(newName, nameof(newName));

        lock (SyncRoot)
        {
            int slot = FindModifiableSlot(fileName);
            var hashEntry = _table.HashEntries[slot];
            if (_table.FindSlotExact(newName, hashEntry.Locale, hashEntry.Platform) >= 0)
                throw new InvalidOperationException($"'{newName}' already exists in the archive.");

            var entry = _table.Entries[(int)(hashEntry.BlockIndex & MpqHashEntry.BlockIndexMask)];
            InvalidateInternalFiles();
            if (entry.Flags.HasFlag(MpqFileFlags.Encrypted))
                MoveRecrypted(entry, fileName, newName);

            _table.RenameSlot(slot, newName);
            _table.RebuildHet();
            _dirty = true;
        }
    }

    /// <summary>
    /// Rewrites the archive without the space of deleted and replaced files (StormLib SFileCompactArchive): pending
    /// changes are flushed, files are copied in file table order right after the header, and the tables are written.
    /// Data before the archive (and user data) is kept.
    /// </summary>
    /// <remarks>
    /// The complete new archive is built in a new temporary file with a random name. An archive opened from a path is
    /// then replaced by it with <see cref="File.Replace(string, string, string?)"/>, so a failure leaves either the old
    /// or the new archive. An archive opened from a stream is overwritten with it; if that fails, the stream is
    /// damaged and the exception names the temporary file, which then holds the complete archive.
    /// </remarks>
    /// <exception cref="InvalidOperationException">A file stream is open, or a file name is unknown (see <see cref="AddListFile"/>).</exception>
    public void Compact()
    {
        ThrowIfDisposed();
        EnsureWritable();

        lock (SyncRoot)
        {
            if (_openFileStreams != 0)
                throw new InvalidOperationException("Close all file streams before compacting the archive.");
            // StormLib CheckIfAllKeysKnown: every file is copied by name.
            if (_table.Entries.Any(e => e.Flags.HasFlag(MpqFileFlags.Exists) && e.FileName is null))
                throw new InvalidOperationException("The archive has files with unknown names; add their names with AddListFile first.");
            // Patch files keep a patch header before their sectors; they are handled with patch chains.
            if (_table.Entries.Any(e => e.Flags.HasFlag(MpqFileFlags.Exists) && e.Flags.HasFlag(MpqFileFlags.PatchFile)
                    && e.Flags.HasFlag(MpqFileFlags.Encrypted) && e.Flags.HasFlag(MpqFileFlags.FixKey)))
                throw new NotSupportedException("Archives with encrypted KEY_V2 patch files cannot be compacted.");
            // Unused block entries are removed by Flush, which also rewrites (attributes) for the new block order.
            if (_dirty || _table.Entries.Any(e => !e.Flags.HasFlag(MpqFileFlags.Exists)))
            {
                _dirty = true;
                Flush();
            }

            // The whole compacted archive (data, tables, header, signature) is built in a new file with a random name
            // (CreateNew never follows or reuses an existing file), next to the archive or in the temp folder.
            string directory = _path is null ? Path.GetTempPath() : Path.GetDirectoryName(_path)!;
            string tempPath = Path.Combine(directory, $"{Path.GetFileName(_path) ?? "mpq"}.{Path.GetRandomFileName()}.tmp");
            var oldHeader = Header;
            var oldPositions = _table.Entries.Select(e => e.FilePosition).ToArray();
            long oldCommittedEnd = _committedEnd;
            bool created = false, replaced = false;
            try
            {
                using (var temp = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    created = true;
                    long[] positions = CopyFilesTo(temp);
                    for (int i = 0; i < positions.Length; i++)
                        _table.Entries[i].FilePosition = positions[i];
                    _table.RebuildHet();
                    // Nothing in the new file needs protecting, so the tables follow the copied data directly.
                    _committedEnd = 0;
                    WriteTablesAndHeader(temp);
                    // StormLib flushes the compacted archive, which signs it again (SSignFileFinish).
                    if (_signatureFlags is not null)
                        FinishWeakSignature(temp);
                    temp.Flush(flushToDisk: true);

                    if (_path is null)
                    {
                        try
                        {
                            temp.Position = 0;
                            _stream.Position = 0;
                            temp.CopyTo(_stream);
                            _stream.SetLength(temp.Length);
                            _stream.Flush();
                            replaced = true;
                        }
                        catch (Exception ex)
                        {
                            // The stream is partly overwritten; the complete copy is kept for recovery.
                            replaced = true;
                            throw new IOException($"Compacting failed while overwriting the stream; the compacted archive is in '{tempPath}'.", ex);
                        }
                    }
                }

                if (_path is not null)
                {
                    _stream.Dispose();
                    try
                    {
                        File.Replace(tempPath, _path, destinationBackupFileName: null);
                        replaced = true;
                    }
                    finally
                    {
                        // The archive file is the original one when the replacement failed.
                        _stream = new FileStream(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                    }
                }
                else
                {
                    TryDelete(tempPath);
                }
                _committedEnd = Header.ArchiveSize;
            }
            catch
            {
                if (replaced)
                {
                    // The archive (or what is left of it) is the compacted one.
                    _committedEnd = Header.ArchiveSize;
                }
                else
                {
                    // The archive is unchanged: restore the state that describes it.
                    Header = oldHeader;
                    for (int i = 0; i < oldPositions.Length; i++)
                        _table.Entries[i].FilePosition = oldPositions[i];
                    _table.RebuildHet();
                    _committedEnd = oldCommittedEnd;
                    if (created)
                        TryDelete(tempPath);
                }
                throw;
            }
        }
    }

    /// <summary>Removes a temporary file; a failure (for example a virus scanner holding it) only leaves it behind.</summary>
    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>
    /// StormLib CopyNonMpqData + CopyMpqFiles: copies everything before the end of the header, then the stored data
    /// of every file (KEY_V2 files re-encrypted for their new position) with raw chunk MD5s (v4).
    /// </summary>
    /// <returns>The new position of every entry.</returns>
    private long[] CopyFilesTo(Stream target)
    {
        CopyRange(_stream, 0, target, _headerOffset + Header.HeaderSize);

        var positions = new long[_table.Entries.Count];
        for (int i = 0; i < _table.Entries.Count; i++)
        {
            var entry = _table.Entries[i];
            positions[i] = entry.FilePosition;
            if (!entry.Flags.HasFlag(MpqFileFlags.Exists))
                continue;

            long position = target.Position - _headerOffset;
            positions[i] = position;
            if (entry.FileSize == 0)
                continue;

            if (entry.Flags.HasFlag(MpqFileFlags.Encrypted) && entry.Flags.HasFlag(MpqFileFlags.FixKey))
            {
                byte[] stored = ReadStored(entry);
                uint oldKey = StormCrypto.GetFileKey(entry.FileName!, entry.FilePosition, entry.FileSize, keyV2: true);
                uint newKey = StormCrypto.GetFileKey(entry.FileName!, position, entry.FileSize, keyV2: true);
                MpqSectorWriter.Recrypt(stored, entry.Flags, entry.FileSize, Header.SectorSize, oldKey, newKey);
                target.Write(stored);
                if (RawChunkSize != 0 && stored.Length != 0)
                    target.Write(ChunkMd5s(stored, RawChunkSize));
            }
            else
            {
                // Copied in chunks: other files need not fit in memory.
                CopyStored(entry, target);
            }
        }
        return positions;
    }

    /// <summary>Copies the stored data of <paramref name="entry"/>, followed by its raw chunk MD5s (v4).</summary>
    private void CopyStored(MpqFileEntry entry, Stream target)
    {
        long source = _headerOffset + entry.FilePosition;
        int chunkSize = RawChunkSize != 0 ? (int)RawChunkSize : 0x10000;
        var buffer = new byte[chunkSize];
        using var md5s = new MemoryStream();
        for (long done = 0; done < entry.CompressedSize;)
        {
            int count = (int)Math.Min(chunkSize, entry.CompressedSize - done);
            _stream.ReadExactlyAt(source + done, buffer.AsSpan(0, count));
            target.Write(buffer, 0, count);
            if (RawChunkSize != 0)
                md5s.Write(MD5.HashData(buffer.AsSpan(0, count)));
            done += count;
        }
        md5s.Position = 0;
        md5s.CopyTo(target);
    }

    /// <summary>
    /// StormLib RecryptFileData, but into a new copy at the end of the archive: the data is re-encrypted with the key of
    /// <paramref name="newName"/> (and the new position for KEY_V2 files) unless the key does not change.
    /// </summary>
    private void MoveRecrypted(MpqFileEntry entry, string oldName, string newName)
    {
        bool keyV2 = entry.Flags.HasFlag(MpqFileFlags.FixKey);
        uint oldKey = StormCrypto.GetFileKey(oldName, entry.FilePosition, entry.FileSize, keyV2);
        if (oldKey == StormCrypto.GetFileKey(newName, entry.FilePosition, entry.FileSize, keyV2) || entry.CompressedSize == 0)
            return;

        long position = FindFreeSpace(includeInternalFiles: false);
        EnsureV1Size(position, entry.CompressedSize);
        uint newKey = StormCrypto.GetFileKey(newName, position, entry.FileSize, keyV2);
        byte[] stored = ReadStored(entry);
        MpqSectorWriter.Recrypt(stored, entry.Flags, entry.FileSize, Header.SectorSize, oldKey, newKey);

        _stream.Position = _headerOffset + position;
        _stream.Write(stored);
        if (RawChunkSize != 0)
            _stream.Write(ChunkMd5s(stored, RawChunkSize));
        entry.FilePosition = position;
    }

    /// <summary>The hash slot of an existing file that can be deleted or renamed.</summary>
    private int FindModifiableSlot(string fileName)
    {
        // StormLib DeleteFileEntry/RenameFileEntry need the hash table entry of the file.
        if (_table.HashTableSize == 0)
            throw new NotSupportedException("Archives without a hash table cannot be modified this way.");
        int slot = _table.FindSlot(fileName);
        return slot >= 0 ? slot : throw new FileNotFoundException($"'{fileName}' was not found in the archive.", fileName);
    }

    /// <exception cref="InvalidDataException">The stored data is larger than the maximum buffer size.</exception>
    private byte[] ReadStored(MpqFileEntry entry)
    {
        if (entry.CompressedSize > _maxBufferSize)
            throw new InvalidDataException("The encrypted file is too large to re-encrypt in memory.");
        var stored = new byte[entry.CompressedSize];
        _stream.ReadExactlyAt(_headerOffset + entry.FilePosition, stored);
        return stored;
    }

    private static void CopyRange(Stream source, long position, Stream target, long count)
    {
        var buffer = new byte[0x10000];
        for (long done = 0; done < count;)
        {
            int chunk = (int)Math.Min(buffer.Length, count - done);
            source.ReadExactlyAt(position + done, buffer.AsSpan(0, chunk));
            target.Write(buffer, 0, chunk);
            done += chunk;
        }
    }
}
