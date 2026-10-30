namespace Biz.Bizadm.MPQ.NET;

/// <summary>Options for <see cref="MpqArchive.Open(Stream, MpqOpenMode, bool, MpqOpenOptions?)"/>.</summary>
public sealed class MpqOpenOptions
{
    public static MpqOpenOptions Default { get; } = new();

    /// <summary>
    /// When true, integrity checks that are ignored by default (such as v4 header and table MD5s, or an unreadable
    /// (listfile) / (attributes)) throw <see cref="InvalidDataException"/>.
    /// </summary>
    public bool Strict { get; init; }

    /// <summary>Additional file names applied after the archive's own (listfile), like StormLib SFileAddListFile.</summary>
    public IEnumerable<string>? ExternalListFile { get; init; }

    /// <summary>
    /// Largest buffer a single file may need in memory: single-unit files, files with patches applied, and patch data.
    /// Sizes come from the archive, so a larger value is rejected with <see cref="InvalidDataException"/> instead of
    /// being allocated. Default 512 MB. Files read sector by sector are not limited.
    /// </summary>
    public int MaxBufferSize { get; init; } = 512 * 1024 * 1024;
}
