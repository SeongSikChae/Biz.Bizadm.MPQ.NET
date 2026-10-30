using System.Buffers.Binary;
using Biz.Bizadm.MPQ.NET.Compression;

namespace Biz.Bizadm.MPQ.NET.Tests.Codecs;

/// <summary>bzip2 and LZMA (SharpCompress) wrappers.</summary>
[TestClass]
public sealed class StreamCodecTests
{
    public static IEnumerable<object[]> Inputs =>
    [
        [Text(17000)], [Random(20000)], [new byte[4096]], [new byte[] { 42 }],
    ];

    [TestMethod]
    [DynamicData(nameof(Inputs))]
    public void BZip2_RoundTrip(byte[] data)
    {
        byte[] compressed = BZip2Codec.Compress(data);
        var output = new byte[data.Length];

        Assert.AreEqual(data.Length, BZip2Codec.Decompress(compressed, output));
        CollectionAssert.AreEqual(data, output);
    }

    [TestMethod]
    [DynamicData(nameof(Inputs))]
    public void Lzma_RoundTripWithStormLibHeader(byte[] data)
    {
        byte[] compressed = LzmaCodec.Compress(data);

        Assert.AreEqual(0, compressed[0], "filter byte");
        Assert.AreEqual((ulong)data.Length, BinaryPrimitives.ReadUInt64LittleEndian(compressed.AsSpan(6)));
        var output = new byte[data.Length];
        Assert.AreEqual(data.Length, LzmaCodec.Decompress(compressed, output));
        CollectionAssert.AreEqual(data, output);
    }

    [TestMethod]
    public void Lzma_RejectsFilterAndShortInput()
    {
        byte[] compressed = LzmaCodec.Compress(Text(1000));
        compressed[0] = 1;
        Assert.ThrowsExactly<InvalidDataException>(() => LzmaCodec.Decompress(compressed, new byte[1000]));
        Assert.ThrowsExactly<InvalidDataException>(() => LzmaCodec.Decompress(new byte[14], new byte[1000]));
    }

    [TestMethod]
    public void BZip2_RejectsGarbage()
    {
        byte[] garbage = Random(300);
        Assert.ThrowsExactly<InvalidDataException>(() => BZip2Codec.Decompress(garbage, new byte[1000]));
    }

    private static byte[] Text(int length) =>
        System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog. ", length / 45 + 1)))[..length];

    private static byte[] Random(int length)
    {
        var data = new byte[length];
        new Random(length).NextBytes(data);
        return data;
    }
}
