using System.IO.Compression;
using Biz.Bizadm.MPQ.NET.Compression;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqCompressionTests
{
    [TestMethod]
    [DataRow(MpqFormatVersion.Version1)]
    [DataRow(MpqFormatVersion.Version2)]
    public void Decompress_Zlib(MpqFormatVersion version)
    {
        byte[] original = Enumerable.Range(0, 4096).Select(i => (byte)(i % 7)).ToArray();
        byte[] input = [(byte)MpqCompressionType.Zlib, .. ZlibCompress(original)];
        var output = new byte[original.Length];

        int written = MpqCompression.Decompress(input, output, version);

        Assert.AreEqual(original.Length, written);
        CollectionAssert.AreEqual(original, output);
    }

    [TestMethod]
    public void Decompress_CopiesWhenSizesAreEqual()
    {
        byte[] input = [0xFF, 1, 2, 3];
        var output = new byte[4];

        Assert.AreEqual(4, MpqCompression.Decompress(input, output, MpqFormatVersion.Version2));
        CollectionAssert.AreEqual(input, output);
    }

    [TestMethod]
    [DataRow((byte)0x04)]
    [DataRow((byte)0x00)]
    public void Decompress_RejectsUnknownV1Mask(byte mask)
    {
        byte[] input = [mask, 1, 2];
        Assert.ThrowsExactly<InvalidDataException>(() => MpqCompression.Decompress(input, new byte[16], MpqFormatVersion.Version1));
    }

    /// <summary>v2+ archives only accept StormLib's fixed list of masks (SCompDecompress2).</summary>
    [TestMethod]
    [DataRow((byte)0x03)]
    [DataRow((byte)0x01)]
    [DataRow((byte)0x0A)]
    public void Decompress_RejectsMaskNotAllowedInV2(byte mask)
    {
        byte[] input = [mask, 1, 2];
        Assert.ThrowsExactly<InvalidDataException>(() => MpqCompression.Decompress(input, new byte[16], MpqFormatVersion.Version2));
    }

    [TestMethod]
    [DataRow(MpqFormatVersion.Version1)]
    [DataRow(MpqFormatVersion.Version2)]
    public void Decompress_MapsCorruptZlibToInvalidData(MpqFormatVersion version)
    {
        byte[] input = [(byte)MpqCompressionType.Zlib, 0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0x00, 0x12];
        Assert.ThrowsExactly<InvalidDataException>(() => MpqCompression.Decompress(input, new byte[64], version));
    }

    /// <summary>StormLib rejects empty output only in v1 (SCompDecompressInternal), not in v2+ (SCompDecompress2).</summary>
    [TestMethod]
    public void Decompress_EmptyOutputFailsOnlyInV1()
    {
        byte[] input = [(byte)MpqCompressionType.Zlib, .. ZlibCompress([])];

        Assert.AreEqual(0, MpqCompression.Decompress(input, new byte[64], MpqFormatVersion.Version2));
        Assert.ThrowsExactly<InvalidDataException>(() => MpqCompression.Decompress(input, new byte[64], MpqFormatVersion.Version1));
    }

    [TestMethod]
    public void Decompress_RejectsInputLargerThanOutput()
    {
        Assert.ThrowsExactly<InvalidDataException>(() => MpqCompression.Decompress(new byte[8], new byte[4], MpqFormatVersion.Version1));
    }

    private static byte[] ZlibCompress(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(data);
        return ms.ToArray();
    }
}
