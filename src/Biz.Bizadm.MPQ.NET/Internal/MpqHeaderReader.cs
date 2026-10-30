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
    public static (MpqHeader Header, MpqUserData? UserData, long HeaderOffset) Find(Stream stream)
    {
        for (long pos = 0; pos + HeaderSizeV1 <= stream.Length; pos += SearchStep)
        {
            uint signature = ReadUInt32At(stream, pos);
            if (signature == UserDataSignature)
            {
                var userData = ReadUserData(stream, pos);
                long headerPos = pos + userData.HeaderOffset;
                if (headerPos + HeaderSizeV1 <= stream.Length && ReadUInt32At(stream, headerPos) == HeaderSignature)
                    return (ReadHeader(stream, headerPos), userData, headerPos);
            }
            else if (signature == HeaderSignature)
            {
                return (ReadHeader(stream, pos), null, pos);
            }
        }
        throw new InvalidDataException("MPQ header not found.");
    }

    private static MpqUserData ReadUserData(Stream stream, long position)
    {
        Span<byte> block = stackalloc byte[UserDataBlockSize];
        ReadAt(stream, position, block);
        uint userDataSize = BinaryPrimitives.ReadUInt32LittleEndian(block[4..]);
        uint headerOffset = BinaryPrimitives.ReadUInt32LittleEndian(block[8..]);
        uint contentSize = BinaryPrimitives.ReadUInt32LittleEndian(block[12..]);

        long available = Math.Max(0, stream.Length - position - UserDataBlockSize);
        var content = new byte[Math.Min(contentSize, available)];
        ReadAt(stream, position + UserDataBlockSize, content);

        return new MpqUserData
        {
            UserDataSize = userDataSize,
            HeaderOffset = headerOffset,
            UserDataHeaderSize = contentSize,
            Content = content,
        };
    }

    private static MpqHeader ReadHeader(Stream stream, long position)
    {
        var buffer = new byte[(int)Math.Min(HeaderSizeV4, stream.Length - position)];
        ReadAt(stream, position, buffer);
        ReadOnlySpan<byte> h = buffer;

        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x04..]);
        var version = (MpqFormatVersion)BinaryPrimitives.ReadUInt16LittleEndian(h[0x0C..]);
        long hashTablePos = BinaryPrimitives.ReadUInt32LittleEndian(h[0x10..]);
        long blockTablePos = BinaryPrimitives.ReadUInt32LittleEndian(h[0x14..]);
        long archiveSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x08..]);
        long hiBlockTablePos = 0, hetTablePos = 0, betTablePos = 0;
        MpqHeaderV4? v4 = null;

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
        }

        return new MpqHeader
        {
            HeaderSize = headerSize,
            FormatVersion = version,
            SectorSizeShift = BinaryPrimitives.ReadUInt16LittleEndian(h[0x0E..]),
            HashTablePosition = hashTablePos,
            BlockTablePosition = blockTablePos,
            HashTableSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x18..]),
            BlockTableSize = BinaryPrimitives.ReadUInt32LittleEndian(h[0x1C..]),
            HiBlockTablePosition = hiBlockTablePos,
            ArchiveSize = archiveSize,
            HetTablePosition = hetTablePos,
            BetTablePosition = betTablePos,
            V4 = v4,
        };
    }

    private static uint ReadUInt32At(Stream stream, long position)
    {
        Span<byte> buffer = stackalloc byte[4];
        ReadAt(stream, position, buffer);
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }

    private static void ReadAt(Stream stream, long position, Span<byte> buffer)
    {
        stream.Position = position;
        stream.ReadExactly(buffer);
    }
}
