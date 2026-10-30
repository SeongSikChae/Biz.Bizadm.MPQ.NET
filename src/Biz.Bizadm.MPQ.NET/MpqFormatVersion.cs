namespace Biz.Bizadm.MPQ.NET;

/// <summary>MPQ header format version (the <c>wFormatVersion</c> field).</summary>
public enum MpqFormatVersion : ushort
{
    /// <summary>Original format, 32-byte header (up to The Burning Crusade).</summary>
    Version1 = 0,

    /// <summary>44-byte header with hi-block table (The Burning Crusade).</summary>
    Version2 = 1,

    /// <summary>68-byte header with HET/BET tables (Cataclysm beta).</summary>
    Version3 = 2,

    /// <summary>208-byte header with table sizes and MD5 checksums (Cataclysm and newer).</summary>
    Version4 = 3,
}
