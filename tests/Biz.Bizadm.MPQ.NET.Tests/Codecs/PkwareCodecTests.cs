using System.Text;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

namespace Biz.Bizadm.MPQ.NET.Tests.Codecs;

[TestClass]
public sealed class PkwareCodecTests
{
    private static byte[] TextData(int length)
    {
        var builder = new StringBuilder();
        int line = 0;
        while (builder.Length < length)
            builder.Append($"Line {line++}: The quick brown fox jumps over the lazy dog. MPQ archives use PKWARE DCL.\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString(0, length));
    }

    private static byte[] RandomData(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    private static void AssertRoundTrip(byte[] original, bool text = false)
    {
        byte[] compressed = text ? PkwareCodec.Compress(original, text: true) : PkwareCodec.Compress(original);

        var output = new byte[original.Length];
        int written = PkwareCodec.Decompress(compressed, output);

        Assert.AreEqual(original.Length, written);
        CollectionAssert.AreEqual(original, output);
    }

    [TestMethod]
    public void RoundTrip_Text()
    {
        AssertRoundTrip(TextData(10_000));
    }

    [TestMethod]
    public void RoundTrip_Text_AsciiMode()
    {
        AssertRoundTrip(TextData(10_000), text: true);
        AssertRoundTrip(RandomData(5000, 7), text: true);
    }

    [TestMethod]
    public void RoundTrip_Random()
    {
        AssertRoundTrip(RandomData(20_000, 1));
    }

    [TestMethod]
    public void RoundTrip_Zeros()
    {
        AssertRoundTrip(new byte[16384]);
        AssertRoundTrip(new byte[100]);
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public void RoundTrip_VerySmall(int length)
    {
        AssertRoundTrip(RandomData(length, length));
        AssertRoundTrip(new byte[length]);
    }

    [TestMethod]
    public void Empty_CompressesToFourBytes_WhichExplodeRejectsLikeStormLib()
    {
        // implode() writes the header and the end literal only; explode() treats
        // input of 4 bytes or less as CMP_BAD_DATA.
        byte[] compressed = PkwareCodec.Compress([]);

        Assert.HasCount(4, compressed);
        Assert.ThrowsExactly<InvalidDataException>(() => PkwareCodec.Decompress(compressed, new byte[1]));
    }

    [TestMethod]
    [DataRow(4096)]
    [DataRow(16384)]
    public void RoundTrip_SectorSizes(int length)
    {
        AssertRoundTrip(TextData(length));
        AssertRoundTrip(RandomData(length, length));
        AssertRoundTrip(new byte[length]);
    }

    [TestMethod]
    [DataRow(0x5FF)]
    [DataRow(0x600)]
    [DataRow(0xBFF)]
    [DataRow(0xC00)]
    [DataRow(0x1000 + 0xFFF)]
    public void RoundTrip_DictionarySizeBoundaries(int length)
    {
        AssertRoundTrip(TextData(length));
    }

    [TestMethod]
    [DataRow(0x5FF, 4)]
    [DataRow(0x600, 5)]
    [DataRow(0xBFF, 5)]
    [DataRow(0xC00, 6)]
    public void Compress_ChoosesDictionarySizeLikeStormLib(int length, int dictBits)
    {
        byte[] compressed = PkwareCodec.Compress(new byte[length]);

        Assert.AreEqual(0, compressed[0]); // CMP_BINARY
        Assert.AreEqual(dictBits, compressed[1]);
    }

    [TestMethod]
    public void Compress_RepetitiveData_IsSmaller()
    {
        byte[] original = TextData(16384);
        Assert.IsLessThan(original.Length / 2, PkwareCodec.Compress(original).Length);
    }

    [TestMethod]
    public void Decompress_OutputSmallerThanData_IsTruncatedLikeStormLib()
    {
        byte[] original = TextData(5000);
        byte[] compressed = PkwareCodec.Compress(original);

        var output = new byte[1000];
        int written = PkwareCodec.Decompress(compressed, output);

        Assert.AreEqual(1000, written);
        CollectionAssert.AreEqual(original[..1000], output);
    }

    [TestMethod]
    public void Decompress_Truncated_Throws()
    {
        byte[] original = TextData(8000);
        byte[] compressed = PkwareCodec.Compress(original);
        var output = new byte[original.Length];

        foreach (int length in new[] { 0, 1, 4, 5, 10, compressed.Length / 2, compressed.Length - 2 })
        {
            Assert.ThrowsExactly<InvalidDataException>(
                () => PkwareCodec.Decompress(compressed.AsSpan(0, length), output),
                $"length {length}");
        }
    }

    [TestMethod]
    public void Decompress_InvalidHeader_Throws()
    {
        var output = new byte[100];

        // Bad compression type
        Assert.ThrowsExactly<InvalidDataException>(() => PkwareCodec.Decompress([2, 4, 0, 0, 0, 0], output));
        // Bad dictionary size
        Assert.ThrowsExactly<InvalidDataException>(() => PkwareCodec.Decompress([0, 3, 0, 0, 0, 0], output));
        Assert.ThrowsExactly<InvalidDataException>(() => PkwareCodec.Decompress([0, 7, 0, 0, 0, 0], output));
    }

    [TestMethod]
    public void Decompress_Garbage_ThrowsOnlyInvalidData()
    {
        var random = new Random(1234);
        var output = new byte[4096];
        int failures = 0;

        for (int i = 0; i < 2000; i++)
        {
            var garbage = new byte[random.Next(5, 600)];
            random.NextBytes(garbage);
            garbage[0] = (byte)random.Next(2);
            garbage[1] = (byte)random.Next(4, 7);

            try
            {
                PkwareCodec.Decompress(garbage, output);
            }
            catch (InvalidDataException)
            {
                failures++;
            }
        }

        Assert.IsGreaterThan(0, failures);
    }
}
