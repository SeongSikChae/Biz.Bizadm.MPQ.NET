namespace Biz.Bizadm.MPQ.NET;

/// <summary>Block table file flags (StormLib MPQ_FILE_*).</summary>
[Flags]
public enum MpqFileFlags : uint
{
    None = 0,

    /// <summary>Compressed with PKWARE Data Compression Library (old style, no compression mask byte).</summary>
    Implode = 0x00000100,

    /// <summary>Compressed with one or more methods given by the compression mask byte of each sector.</summary>
    Compress = 0x00000200,

    Encrypted = 0x00010000,

    /// <summary>The file key is adjusted by the file position and size (StormLib MPQ_FILE_KEY_V2, formerly FIX_KEY).</summary>
    FixKey = 0x00020000,

    /// <summary>The file is an incremental patch (PTCH).</summary>
    PatchFile = 0x00100000,

    /// <summary>The file is stored as a single unit instead of sectors.</summary>
    SingleUnit = 0x01000000,

    DeleteMarker = 0x02000000,

    /// <summary>A CRC table follows the sector offset table.</summary>
    SectorCrc = 0x04000000,

    /// <summary>The file is the (signature) file.</summary>
    Signature = 0x10000000,

    Exists = 0x80000000,
}
