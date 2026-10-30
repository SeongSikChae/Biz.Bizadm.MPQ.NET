namespace Biz.Bizadm.MPQ.NET;

/// <summary>Result of <see cref="MpqArchive.VerifySignature()"/> (StormLib SFileVerifyArchive codes).</summary>
public enum MpqSignatureStatus
{
    /// <summary>The archive has no signature.</summary>
    None = 0,

    /// <summary>
    /// The (signature) file matches the archive. The weak signing key is public, so this only detects damage, not
    /// tampering.
    /// </summary>
    WeakValid = 2,

    /// <summary>The archive has a (signature) file, but the weak signature does not match.</summary>
    WeakInvalid = 3,

    /// <summary>The "NGIS" signature after the archive matches one of the known Blizzard public keys.</summary>
    StrongValid = 4,

    /// <summary>The archive has a strong signature, but it does not match any known Blizzard public key.</summary>
    StrongInvalid = 5,

    /// <summary>
    /// The archive has a (signature) file whose signature is all zero, so nothing was checked. StormLib reports this
    /// as a valid weak signature.
    /// </summary>
    WeakUnsigned = 6,
}
