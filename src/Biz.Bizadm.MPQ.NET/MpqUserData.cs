namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// The "MPQ\x1B" user data block that precedes the MPQ header, used by StarCraft II replays and maps.
/// </summary>
public sealed record MpqUserData
{
    /// <summary>Maximum size of the user data (<c>cbUserDataSize</c>).</summary>
    public required uint UserDataSize { get; init; }

    /// <summary>Offset of the MPQ header, relative to the start of the user data block.</summary>
    public required uint HeaderOffset { get; init; }

    /// <summary>Size of the user data content that follows the 16-byte block header (<c>cbUserDataHeader</c>).</summary>
    public required uint UserDataHeaderSize { get; init; }

    /// <summary>The user data content (for SC2 replays, the serialized replay header).</summary>
    public required ReadOnlyMemory<byte> Content { get; init; }
}
