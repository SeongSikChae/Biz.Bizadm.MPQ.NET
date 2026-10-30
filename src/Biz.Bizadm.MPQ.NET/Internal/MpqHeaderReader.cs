using System.Buffers.Binary;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Finds and parses the MPQ header and the optional "MPQ\x1B" user data block (StormLib TMPQHeader layout).</summary>
internal static class MpqHeaderReader
{
    internal const uint HeaderSignature = 0x1A51504D;   // "MPQ\x1A"
    internal const uint UserDataSignature = 0x1B51504D; // "MPQ\x1B"

    internal const int HeaderSizeV1 = 0x20;
    internal const int HeaderSizeV2 = 0x2C;
    internal const int HeaderSizeV3 = 0x44;
    internal const int HeaderSizeV4 = 0xD0;

    private const int SearchStep = 0x200;
    private const int UserDataBlockSize = 0x10;

    /// <summary>Searches the stream at 512-byte steps for the MPQ header, following a user data block when present.</summary>
    /// <returns>The header, the user data (or null) and the absolute position of the MPQ header.</returns>
    /// <param name="strict">Verify the v4 header MD5 (MD5_MpqHeader over the first 0xC0 bytes) and throw on mismatch.</param>
    /// <remarks>
    /// Like StormLib, a header whose size field is below 0x20 or that is recognized as fake (tables outside the file) is
    /// skipped and the search continues. The returned header has <see cref="MpqHeader.Malformed"/> set when it was repaired.
    /// </remarks>
    public static (MpqHeader Header, MpqUserData? UserData, long HeaderOffset) Find(Stream stream, bool strict = false)
    {
        for (long pos = 0; pos + HeaderSizeV1 <= stream.Length; pos += SearchStep)
        {
            uint signature = ReadUInt32At(stream, pos);
            if (signature == UserDataSignature)
            {
                var userData = ReadUserData(stream, pos);
                long headerPos = pos + userData.HeaderOffset;
                // StormLib checks the header with the offset of the user data; the header offset is added afterwards.
                if (headerPos + HeaderSizeV1 <= stream.Length && IsHeaderCandidate(stream, headerPos)
                    && ReadHeader(stream, headerPos, pos, strict) is { } header)
                    return (header, userData, headerPos);
            }
            else if (signature == HeaderSignature && IsHeaderCandidate(stream, pos) && ReadHeader(stream, pos, pos, strict) is { } header)
            {
                return (header, null, pos);
            }
        }
        throw new InvalidDataException("MPQ header not found.");
    }

    /// <summary>StormLib SFileOpenArchive: the signature with a header size of at least 0x20 (Warcraft III Storm.dll check).</summary>
    private static bool IsHeaderCandidate(Stream stream, long position) =>
        ReadUInt32At(stream, position) == HeaderSignature && ReadUInt32At(stream, position + 4) >= HeaderSizeV1;

    /// <summary>
    /// File position of an MPQ offset (StormLib FileOffsetFromMpqOffset): v1 archives use 32-bit positions, so the sum
    /// wraps (protectors put tables before the header that way).
    /// </summary>
    public static long FileOffset(MpqFormatVersion version, long headerOffset, long offset) =>
        version == MpqFormatVersion.Version1 ? (headerOffset + offset) & 0xFFFFFFFF : headerOffset + offset;

    private static MpqUserData ReadUserData(Stream stream, long position)
    {
        Span<byte> block = stackalloc byte[UserDataBlockSize];
        stream.ReadExactlyAt(position, block);
        uint userDataSize = BinaryPrimitives.ReadUInt32LittleEndian(block[4..]);
        uint headerOffset = BinaryPrimitives.ReadUInt32LittleEndian(block[8..]);
        uint contentSize = BinaryPrimitives.ReadUInt32LittleEndian(block[12..]);

        long available = Math.Max(0, stream.Length - position - UserDataBlockSize);
        var content = new byte[Math.Min(contentSize, available)];
        stream.ReadExactlyAt(position + UserDataBlockSize, content);

        return new MpqUserData
        {
            UserDataSize = userDataSize,
            HeaderOffset = headerOffset,
            UserDataHeaderSize = contentSize,
            Content = content,
        };
    }

    /// <summary>StormLib ConvertMpqHeaderToFormat4.</summary>
    /// <param name="headerPosition">Position of the header.</param>
    /// <param name="position">
    /// StormLib ByteOffset: the search position, which is the user data block (not the header) when there is one.
    /// </param>
    /// <returns>Null for a fake header (ERROR_FAKE_MPQ_HEADER), so the search continues.</returns>
    /// <exception cref="InvalidDataException">The header is corrupt (ERROR_FILE_CORRUPT).</exception>
    private static MpqHeader? ReadHeader(Stream stream, long headerPosition, long position, bool strict)
    {
        long fileSize = stream.Length;
        var buffer = new byte[(int)Math.Min(HeaderSizeV4, fileSize - headerPosition)];
        stream.ReadExactlyAt(headerPosition, buffer);
        ReadOnlySpan<byte> h = buffer;

        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x04..]);
        ushort rawVersion = BinaryPrimitives.ReadUInt16LittleEndian(h[0x0C..]);
        var version = (MpqFormatVersion)rawVersion;
        ushort sectorSizeShift = BinaryPrimitives.ReadUInt16LittleEndian(h[0x0E..]);
        uint hashTableSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x18..]);
        uint blockTableSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x1C..]);
        bool malformed = false;

        // StormLib reads unknown format versions and v2 headers of another size as malformed v1 headers.
        if (version > MpqFormatVersion.Version4
            || version == MpqFormatVersion.Version2 && (headerSize != HeaderSizeV2 || h.Length < HeaderSizeV2))
        {
            version = MpqFormatVersion.Version1;
            headerSize = HeaderSizeV1;
            malformed = true;
        }
        long hashTablePos = BinaryPrimitives.ReadUInt32LittleEndian(h[0x10..]);
        long blockTablePos = BinaryPrimitives.ReadUInt32LittleEndian(h[0x14..]);
        long archiveSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x08..]);
        long hiBlockTablePos = 0, hetTablePos = 0, betTablePos = 0;
        MpqHeaderV4? v4 = null;

        if (version == MpqFormatVersion.Version1)
        {
            if (!malformed)
            {
                // Blatantly wrong headers point their tables outside the file.
                if (((position + hashTablePos) & 0xFFFFFFFF) > fileSize || ((position + blockTablePos) & 0xFFFFFFFF) > fileSize)
                    return null;
                if (headerSize != HeaderSizeV1)
                {
                    headerSize = HeaderSizeV1;
                    malformed = true;
                }
            }

            if (blockTableSize > 1 && (hashTablePos <= headerSize || (hashTablePos & 0x80000000) != 0
                || blockTablePos <= headerSize || (blockTablePos & 0x80000000) != 0))
                malformed = true;

            // Only the low byte of the sector size is used.
            if ((sectorSizeShift & 0xFF00) != 0)
                malformed = true;
            sectorSizeShift &= 0xFF;

            // The block table position is a 32-bit value; the BOBA protector puts the table before the header.
            long blockTablePos64 = (uint)(position + blockTablePos);
            if (malformed)
                archiveSize = DetermineArchiveSizeV1(stream, position, archiveSize, blockTablePos, blockTableSize);
            // EWIX_v8_7.w3x: the block table size is cut to the file.
            if (blockTablePos64 + blockTableSize * 16L > fileSize)
                blockTableSize = (uint)((fileSize - blockTablePos64) / 16);
            if (blockTablePos64 < position)
                malformed = true;

            return new MpqHeader
            {
                HeaderSize = headerSize,
                FormatVersion = version,
                SectorSizeShift = sectorSizeShift,
                HashTablePosition = hashTablePos,
                BlockTablePosition = blockTablePos,
                HashTableSize = hashTableSize,
                BlockTableSize = blockTableSize,
                ArchiveSize = archiveSize,
                Malformed = malformed,
            };
        }

        if (version >= MpqFormatVersion.Version2 && h.Length >= HeaderSizeV2)
        {
            hiBlockTablePos = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x20..]);
            hashTablePos |= (long)BinaryPrimitives.ReadUInt16LittleEndian(h[0x28..]) << 32;
            blockTablePos |= (long)BinaryPrimitives.ReadUInt16LittleEndian(h[0x2A..]) << 32;
        }

        if (version >= MpqFormatVersion.Version3 && headerSize >= HeaderSizeV3 && h.Length >= HeaderSizeV3)
        {
            archiveSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x2C..]);
            betTablePos = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x34..]);
            hetTablePos = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x3C..]);
        }

        if (version >= MpqFormatVersion.Version4 && headerSize >= HeaderSizeV4 && h.Length >= HeaderSizeV4)
        {
            v4 = new MpqHeaderV4
            {
                HashTableSize64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x44..]),
                BlockTableSize64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x4C..]),
                HiBlockTableSize64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x54..]),
                HetTableSize64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x5C..]),
                BetTableSize64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(h[0x64..]),
                RawChunkSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x6C..]),
                Md5BlockTable = buffer.AsMemory(0x70, 0x10),
                Md5HashTable = buffer.AsMemory(0x80, 0x10),
                Md5HiBlockTable = buffer.AsMemory(0x90, 0x10),
                Md5BetTable = buffer.AsMemory(0xA0, 0x10),
                Md5HetTable = buffer.AsMemory(0xB0, 0x10),
                Md5MpqHeader = buffer.AsMemory(0xC0, 0x10),
            };
            MpqTableReader.VerifyMd5(h[..0xC0], v4.Md5MpqHeader, strict, "MPQ header");
        }

        switch (version)
        {
            case MpqFormatVersion.Version2:
                if (hiBlockTablePos > fileSize)
                    throw new InvalidDataException("The hi-block table lies outside the file.");
                // The block table must follow the hash table.
                if (blockTablePos < hashTablePos)
                    malformed = true;
                break;

            case MpqFormatVersion.Version3:
            {
                // Tables are in the order HET, BET, hash, block, hi-block; each must lie in the file.
                long maxOffset = archiveSize;
                if (hiBlockTablePos != 0)
                {
                    if (hiBlockTablePos > fileSize)
                        throw new InvalidDataException("An archive table lies outside the file.");
                    maxOffset = hiBlockTablePos;
                }
                foreach (long tablePos in new[] { blockTablePos, hashTablePos })
                {
                    if (tablePos == 0)
                        continue;
                    if (tablePos > fileSize || tablePos >= maxOffset)
                        throw new InvalidDataException("An archive table lies outside the file.");
                    maxOffset = tablePos;
                }
                if (betTablePos > fileSize || hetTablePos > fileSize)
                    throw new InvalidDataException("An archive table lies outside the file.");
                break;
            }

            case MpqFormatVersion.Version4 when v4 is not null:
                // HiBlockTable must be 0 for archives under 4 GB, and one table pair must lie in the file.
                if (archiveSize >> 32 == 0 && hiBlockTablePos != 0)
                    return null;
                bool hetBetOk = TablePositionOk(position, hetTablePos, v4.HetTableSize64, fileSize)
                    && TablePositionOk(position, betTablePos, v4.BetTableSize64, fileSize);
                bool hashBlockOk = TablePositionOk(position, (uint)hashTablePos, v4.HashTableSize64, fileSize)
                    && TablePositionOk(position, (uint)blockTablePos, v4.BlockTableSize64, fileSize);
                if (!hetBetOk && !hashBlockOk)
                    return null;
                if ((ulong)position + (ulong)archiveSize > (ulong)fileSize || position + hiBlockTablePos >= fileSize)
                {
                    malformed = true;
                    archiveSize = DetermineArchiveSizeV4(v4, hetTablePos, betTablePos, hashTablePos, blockTablePos, hashTableSize, blockTableSize);
                }
                break;
        }

        return new MpqHeader
        {
            HeaderSize = headerSize,
            FormatVersion = version,
            SectorSizeShift = sectorSizeShift,
            HashTablePosition = hashTablePos,
            BlockTablePosition = blockTablePos,
            HashTableSize = hashTableSize,
            BlockTableSize = blockTableSize,
            HiBlockTablePosition = hiBlockTablePos,
            ArchiveSize = archiveSize,
            HetTablePosition = hetTablePos,
            BetTablePosition = betTablePos,
            V4 = v4,
            Malformed = malformed,
        };
    }

    /// <summary>StormLib VerifyTablePosition64.</summary>
    private static bool TablePositionOk(long mpqOffset, long tableOffset, long tableSize, long fileSize)
    {
        if (tableOffset == 0)
            return true;
        ulong offset = (ulong)mpqOffset, table = (ulong)tableOffset, size = (ulong)tableSize, file = (ulong)fileSize;
        if (offset + table < offset || offset + table + size < offset)
            return false;
        return table < file && size < file && offset + table < file && offset + table + size < file;
    }

    /// <summary>StormLib DetermineArchiveSize_V1: the header size if plausible, otherwise the file end (before a strong signature).</summary>
    private static long DetermineArchiveSizeV1(Stream stream, long mpqOffset, long archiveSize, long blockTablePos, uint blockTableSize)
    {
        if (blockTablePos < archiveSize)
        {
            // The block table cannot be compressed, so the sizes must match.
            if ((uint)(archiveSize - blockTablePos) == blockTableSize * 16L)
                return archiveSize;
            if ((uint)archiveSize == (uint)(stream.Length - mpqOffset))
                return archiveSize;
        }

        long end = stream.Length;
        if (end - mpqOffset > MpqSignature.StrongSize + 4 && ReadUInt32At(stream, end - MpqSignature.StrongSize - 4) == MpqSignature.StrongId)
            end -= MpqSignature.StrongSize + 4;
        return end - mpqOffset;
    }

    /// <summary>StormLib DetermineArchiveSize_V4: the end of the furthest table.</summary>
    private static long DetermineArchiveSizeV4(MpqHeaderV4 v4, long hetPos, long betPos, long hashPos, long blockPos, uint hashCount, uint blockCount)
    {
        long size = 0;
        if (betPos >> 32 == 0 && v4.BetTableSize64 >> 32 == 0)
            size = Math.Max(size, betPos + v4.BetTableSize64);
        if (hetPos >> 32 == 0 && v4.HetTableSize64 >> 32 == 0)
            size = Math.Max(size, hetPos + v4.HetTableSize64);
        size = Math.Max(size, (uint)hashPos + hashCount * 16L);
        size = Math.Max(size, (uint)blockPos + blockCount * 16L);
        return size;
    }

    private static uint ReadUInt32At(Stream stream, long position)
    {
        Span<byte> buffer = stackalloc byte[4];
        stream.ReadExactlyAt(position, buffer);
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }
}
