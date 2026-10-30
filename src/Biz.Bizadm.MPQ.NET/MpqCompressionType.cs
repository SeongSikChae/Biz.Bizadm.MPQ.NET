namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// Sector compression mask (StormLib MPQ_COMPRESSION_*). Values other than <see cref="Lzma"/> can be combined.
/// </summary>
public enum MpqCompressionType : byte
{
    None = 0,
    Huffman = 0x01,
    Zlib = 0x02,
    Pkware = 0x08,
    BZip2 = 0x10,
    Sparse = 0x20,
    AdpcmMono = 0x40,
    AdpcmStereo = 0x80,

    /// <summary>LZMA (v2+ archives only); not a combinable flag. In v1 archives 0x12 means BZip2 | Zlib.</summary>
    Lzma = 0x12,
}
