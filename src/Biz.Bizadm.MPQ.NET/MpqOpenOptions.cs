namespace Biz.Bizadm.MPQ.NET;

/// <summary>Options for <see cref="MpqArchive.Open(Stream, MpqOpenMode, bool, MpqOpenOptions?)"/>.</summary>
public sealed class MpqOpenOptions
{
    public static MpqOpenOptions Default { get; } = new();

    /// <summary>
    /// When true, integrity checks that are ignored by default (such as v4 header and table MD5s) throw
    /// <see cref="InvalidDataException"/>.
    /// </summary>
    public bool Strict { get; init; }
}
