namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// Sector compression mask (StormLib MPQ_COMPRESSION_*). Values other than <see cref="Lzma"/> can be combined.
/// </summary>
public enum MpqCompressionType : byte
{
    /// <summary>No compression.</summary>
    None = 0,

    /// <summary>Huffman compression.</summary>
    Huffman = 0x01,

    /// <summary>zlib (RFC 1950).</summary>
    Zlib = 0x02,

    /// <summary>PKWARE Data Compression Library (implode/explode).</summary>
    Pkware = 0x08,

    /// <summary>bzip2.</summary>
    BZip2 = 0x10,

    /// <summary>Sparse (zero-run) compression.</summary>
    Sparse = 0x20,

    /// <summary>IMA ADPCM mono.</summary>
    AdpcmMono = 0x40,

    /// <summary>IMA ADPCM stereo.</summary>
    AdpcmStereo = 0x80,

    /// <summary>LZMA (v2+ archives only); not a combinable flag. In v1 archives 0x12 means BZip2 | Zlib.</summary>
    Lzma = 0x12,
}
