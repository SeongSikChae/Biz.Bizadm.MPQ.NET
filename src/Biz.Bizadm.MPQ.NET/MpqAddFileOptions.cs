namespace Biz.Bizadm.MPQ.NET;

/// <summary>Options for <see cref="MpqArchive.AddFile(string, Stream, MpqAddFileOptions?)"/>.</summary>
public sealed class MpqAddFileOptions
{
    public static MpqAddFileOptions Default { get; } = new();

    /// <summary>Sector compression; <see cref="MpqCompressionType.None"/> stores the file uncompressed.</summary>
    public MpqCompressionType Compression { get; init; } = MpqCompressionType.Zlib;

    public bool Encrypt { get; init; }

    /// <summary>Adjust the encryption key by file position and size (MPQ_FILE_KEY_V2). Requires <see cref="Encrypt"/>.</summary>
    public bool FixKey { get; init; }

    /// <summary>Store the file as one unit instead of sectors. Ignored for archives created as v1 (as in StormLib).</summary>
    public bool SingleUnit { get; init; }

    /// <summary>Store an adler32 checksum per sector. Ignored for single-unit or uncompressed files.</summary>
    public bool SectorCrc { get; init; }

    public ushort Locale { get; init; }

    /// <summary>Replace a file with the same name and locale instead of throwing.</summary>
    public bool Overwrite { get; init; }
}
