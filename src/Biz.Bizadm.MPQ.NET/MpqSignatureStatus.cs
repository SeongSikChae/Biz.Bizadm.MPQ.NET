namespace Biz.Bizadm.MPQ.NET;

/// <summary>Result of <see cref="MpqArchive.VerifySignature"/> (StormLib SFileVerifyArchive codes).</summary>
public enum MpqSignatureStatus
{
    /// <summary>The archive has no signature.</summary>
    None = 0,

    /// <summary>The (signature) file matches the archive, or is all zero (not signed yet).</summary>
    WeakValid = 2,

    WeakInvalid = 3,

    /// <summary>The "NGIS" signature after the archive matches one of the known Blizzard public keys.</summary>
    StrongValid = 4,

    StrongInvalid = 5,
}
