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
    /// An archive opened from a path is rebuilt in a temporary file that then replaces it; otherwise the stream is
    /// overwritten. Data before the archive (and user data) is kept.
    /// </summary>
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

            // The temporary file is next to the archive, or in the temp folder for archives opened from a stream.
            string tempPath = _path is null ? Path.GetTempFileName() : _path + ".tmp";
            long[] positions;
            using (var temp = new FileStream(tempPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                try
                {
                    positions = CopyFilesTo(temp);
                }
                catch
                {
                    temp.Dispose();
                    File.Delete(tempPath);
                    throw;
                }

                if (_path is null)
                {
                    try
                    {
                        temp.Position = 0;
                        _stream.Position = 0;
                        temp.CopyTo(_stream);
                        _stream.SetLength(temp.Length);
                    }
                    catch (Exception ex)
                    {
                        // The stream is partly overwritten; the complete copy is kept for recovery.
                        throw new IOException($"Compacting failed while overwriting the stream; the compacted archive is in '{tempPath}'.", ex);
                    }
                }
            }

            if (_path is null)
            {
                File.Delete(tempPath);
            }
            else
            {
                _stream.Dispose();
                try
                {
                    File.Replace(tempPath, _path, destinationBackupFileName: null);
                }
                catch
                {
                    File.Delete(tempPath);
                    throw;
                }
                finally
                {
                    _stream = new FileStream(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                }
            }

            for (int i = 0; i < positions.Length; i++)
                _table.Entries[i].FilePosition = positions[i];
            _table.RebuildHet();
            WriteTablesAndHeader();
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

            byte[] stored = ReadStored(entry);
            if (entry.Flags.HasFlag(MpqFileFlags.Encrypted) && entry.Flags.HasFlag(MpqFileFlags.FixKey))
            {
                uint oldKey = StormCrypto.GetFileKey(entry.FileName!, entry.FilePosition, entry.FileSize, keyV2: true);
                uint newKey = StormCrypto.GetFileKey(entry.FileName!, position, entry.FileSize, keyV2: true);
                MpqSectorWriter.Recrypt(stored, entry.Flags, entry.FileSize, Header.SectorSize, oldKey, newKey);
            }
            target.Write(stored);
            if (RawChunkSize != 0 && stored.Length != 0)
                target.Write(ChunkMd5s(stored, RawChunkSize));
        }
        return positions;
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

    private byte[] ReadStored(MpqFileEntry entry)
    {
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
