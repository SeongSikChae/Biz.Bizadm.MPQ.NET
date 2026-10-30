namespace Biz.Bizadm.MPQ.NET;

/// <summary>A file in an MPQ archive.</summary>
public sealed record MpqEntry
{
    /// <summary>File name as stored in the archive, or null when it is not known.</summary>
    public string? Name { get; init; }

    /// <summary>Index in the block table.</summary>
    public required int BlockIndex { get; init; }

    /// <summary>Uncompressed file size in bytes.</summary>
    public required long FileSize { get; init; }

    /// <summary>Compressed (on-disk) size in bytes.</summary>
    public required long CompressedSize { get; init; }

    /// <summary>Block table flags.</summary>
    public required MpqFileFlags Flags { get; init; }

    /// <summary>Locale of the hash table slot (0 = neutral).</summary>
    public required ushort Locale { get; init; }
}
