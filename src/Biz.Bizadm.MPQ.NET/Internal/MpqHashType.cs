namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Hash types used with <see cref="StormCrypto.HashString(ReadOnlySpan{char}, MpqHashType)"/>.</summary>
internal enum MpqHashType
{
    /// <summary>Start index in the hash table.</summary>
    TableOffset = 0,

    /// <summary>First name check value (HashA).</summary>
    NameA = 1,

    /// <summary>Second name check value (HashB).</summary>
    NameB = 2,

    /// <summary>Encryption key of tables and files.</summary>
    FileKey = 3,
}
