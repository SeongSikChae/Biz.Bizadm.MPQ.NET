namespace Biz.Bizadm.MPQ.NET;

/// <summary>Access mode for <see cref="MpqArchive.Open(string, MpqOpenMode, MpqOpenOptions?)"/>.</summary>
public enum MpqOpenMode
{
    /// <summary>Read only.</summary>
    Read,

    /// <summary>Read and modify the archive in place.</summary>
    ReadWrite,
}
