namespace Biz.Bizadm.MPQ.NET;

/// <summary>Options for <see cref="MpqArchive.Create(Stream, MpqArchiveCreateOptions?, bool)"/>.</summary>
public sealed class MpqArchiveCreateOptions
{
    /// <summary>Default options.</summary>
    public static MpqArchiveCreateOptions Default { get; } = new();

    /// <summary>Header format version of the new archive.</summary>
    public MpqFormatVersion FormatVersion { get; init; } = MpqFormatVersion.Version1;

    /// <summary>Sector size is 512 &lt;&lt; <see cref="SectorSizeShift"/> (default 3: 4096 bytes).</summary>
    public int SectorSizeShift { get; init; } = 3;

    /// <summary>
    /// Number of hash table entries; a power of two. This is also the maximum number of files, including (listfile)
    /// and (attributes), whose entries are reserved (StormLib dwReservedFiles).
    /// </summary>
    public int HashTableSize { get; init; } = 0x1000;

    /// <summary>Maintain a (listfile) with the names of all files.</summary>
    public bool CreateListFile { get; init; } = true;

    /// <summary>Maintain an (attributes) file with CRC32, file time and MD5 of every file.</summary>
    public bool CreateAttributes { get; init; } = true;
}
