namespace Biz.Bizadm.MPQ.NET;

/// <summary>Options for <see cref="MpqArchive.Open(Stream, MpqOpenMode, bool, MpqOpenOptions?)"/>.</summary>
public sealed class MpqOpenOptions
{
    public static MpqOpenOptions Default { get; } = new();
}
