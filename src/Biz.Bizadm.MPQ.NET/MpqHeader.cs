namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// MPQ archive header. Table positions are relative to the start of the MPQ header.
/// </summary>
public sealed record MpqHeader
{
    public required uint HeaderSize { get; init; }
    public required MpqFormatVersion FormatVersion { get; init; }

    /// <summary>Power of two exponent of the sector size: 512 &lt;&lt; <see cref="SectorSizeShift"/>.</summary>
    public required ushort SectorSizeShift { get; init; }

    /// <summary>Hash table position; v2+ includes <c>wHashTablePosHi</c>.</summary>
    public required long HashTablePosition { get; init; }

    /// <summary>Block table position; v2+ includes <c>wBlockTablePosHi</c>.</summary>
    public required long BlockTablePosition { get; init; }

    /// <summary>Number of hash table entries.</summary>
    public required uint HashTableSize { get; init; }

    /// <summary>Number of block table entries.</summary>
    public required uint BlockTableSize { get; init; }

    /// <summary>Hi-block table position (v2+), or 0 when there is none.</summary>
    public long HiBlockTablePosition { get; init; }

    /// <summary>Archive size: <c>dwArchiveSize</c> for v1/v2, <c>ArchiveSize64</c> for v3+.</summary>
    public required long ArchiveSize { get; init; }

    /// <summary>HET table position (v3+), or 0 when there is none.</summary>
    public long HetTablePosition { get; init; }

    /// <summary>BET table position (v3+), or 0 when there is none.</summary>
    public long BetTablePosition { get; init; }

    /// <summary>Version 4 fields, or null for older headers.</summary>
    public MpqHeaderV4? V4 { get; init; }

    public int SectorSize => 0x200 << SectorSizeShift;
}

/// <summary>Version 4 header fields: compressed table sizes and MD5 checksums.</summary>
public sealed record MpqHeaderV4
{
    public required long HashTableSize64 { get; init; }
    public required long BlockTableSize64 { get; init; }
    public required long HiBlockTableSize64 { get; init; }
    public required long HetTableSize64 { get; init; }
    public required long BetTableSize64 { get; init; }

    /// <summary>Size of the raw data chunks whose MD5 follows the file data.</summary>
    public required uint RawChunkSize { get; init; }

    public required ReadOnlyMemory<byte> Md5BlockTable { get; init; }
    public required ReadOnlyMemory<byte> Md5HashTable { get; init; }
    public required ReadOnlyMemory<byte> Md5HiBlockTable { get; init; }
    public required ReadOnlyMemory<byte> Md5BetTable { get; init; }
    public required ReadOnlyMemory<byte> Md5HetTable { get; init; }

    /// <summary>MD5 of the first 0xC0 bytes of the header.</summary>
    public required ReadOnlyMemory<byte> Md5MpqHeader { get; init; }
}
