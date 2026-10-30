namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Combined file entry, one per block table entry (StormLib TFileEntry). Hash fields come from the
/// first hash table slot that references the block.
/// </summary>
internal sealed class MpqFileEntry
{
    /// <summary>Name resolved from a list file or a lookup; null when unknown.</summary>
    public string? FileName { get; set; }

    /// <summary>64-bit Jenkins name hash used by HET/BET tables (v3+).</summary>
    public ulong NameHash { get; set; }

    public uint HashA { get; set; }
    public uint HashB { get; set; }
    public ushort Locale { get; set; }
    public byte Platform { get; set; }

    /// <summary>File position relative to the MPQ header (64-bit with the hi-block table).</summary>
    public long FilePosition { get; set; }

    public uint CompressedSize { get; set; }
    public uint FileSize { get; set; }
    public MpqFileFlags Flags { get; set; }
}
