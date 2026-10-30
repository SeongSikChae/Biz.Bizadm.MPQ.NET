using System.Text;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

namespace Biz.Bizadm.MPQ.NET.Tests.Codecs;

[TestClass]
public sealed class HuffmanCodecTests
{
    public static IEnumerable<object[]> RoundTripCases()
    {
        foreach (int type in new[] { 0, 6, 7, 8 })
        {
            foreach (string kind in new[] { "text", "random", "zeros" })
            {
                foreach (int size in new[] { 1, 4096, 16 * 1024 })
                    yield return [type, kind, size];
            }
        }
    }

    [TestMethod]
    [DynamicData(nameof(RoundTripCases))]
    public void RoundTrip_RestoresInput(int compressionType, string kind, int size)
    {
        byte[] input = CreateInput(kind, size);

        byte[] compressed = HuffmanCodec.Compress(input, compressionType);
        var output = new byte[input.Length];
        int written = HuffmanCodec.Decompress(compressed, output);

        Assert.AreEqual((byte)compressionType, compressed[0]);
        Assert.AreEqual(input.Length, written);
        CollectionAssert.AreEqual(input, output);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(6)]
    [DataRow(7)]
    [DataRow(8)]
    public void Compress_IsDeterministic(int compressionType)
    {
        byte[] input = CreateInput("text", 4096);

        CollectionAssert.AreEqual(HuffmanCodec.Compress(input, compressionType), HuffmanCodec.Compress(input, compressionType));
    }

    [TestMethod]
    public void Compress_TextShrinks()
    {
        byte[] input = CreateInput("text", 16 * 1024);

        Assert.IsLessThan(input.Length, HuffmanCodec.Compress(input, 0).Length);
    }

    [TestMethod]
    public void Compress_EmptyInput_DecompressFailsLikeStormLib()
    {
        // Type byte plus end-of-stream symbol; zero decoded bytes is a failure in Decompress_huff
        byte[] compressed = HuffmanCodec.Compress([], 0);

        Assert.AreEqual(0, compressed[0]);
        Assert.ThrowsExactly<InvalidDataException>(() => HuffmanCodec.Decompress(compressed, new byte[16]));
    }

    [TestMethod]
    public void Decompress_ShortOutput_StopsAtOutputLength()
    {
        byte[] input = CreateInput("text", 4096);
        byte[] compressed = HuffmanCodec.Compress(input, 0);
        var output = new byte[100];

        int written = HuffmanCodec.Decompress(compressed, output);

        Assert.AreEqual(100, written);
        CollectionAssert.AreEqual(input[..100], output);
    }

    [TestMethod]
    public void Decompress_EmptyInput_Throws()
    {
        Assert.ThrowsExactly<InvalidDataException>(() => HuffmanCodec.Decompress([], new byte[16]));
    }

    [TestMethod]
    public void Decompress_EmptyOutput_Throws()
    {
        byte[] compressed = HuffmanCodec.Compress(CreateInput("text", 64), 0);

        Assert.ThrowsExactly<InvalidDataException>(() => HuffmanCodec.Decompress(compressed, Span<byte>.Empty));
    }

    [TestMethod]
    public void Decompress_UnknownDataType_Throws()
    {
        Assert.ThrowsExactly<InvalidDataException>(() => HuffmanCodec.Decompress([0x09, 0xFF, 0xFF, 0xFF], new byte[16]));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(6)]
    [DataRow(7)]
    [DataRow(8)]
    public void Decompress_Truncated_Throws(int compressionType)
    {
        byte[] input = CreateInput("random", 4096);
        byte[] compressed = HuffmanCodec.Compress(input, compressionType);

        foreach (int length in new[] { 1, 2, compressed.Length / 2, compressed.Length - 2 })
        {
            byte[] truncated = compressed[..length];
            Assert.ThrowsExactly<InvalidDataException>(
                () => HuffmanCodec.Decompress(truncated, new byte[input.Length]),
                $"length {length}");
        }
    }

    [TestMethod]
    public void Decompress_Garbage_ThrowsOnlyInvalidData()
    {
        var random = new Random(1234);
        var output = new byte[4096];

        for (int i = 0; i < 2000; i++)
        {
            var garbage = new byte[random.Next(1, 600)];
            random.NextBytes(garbage);
            garbage[0] = (byte)random.Next(0, 9);

            try
            {
                int written = HuffmanCodec.Decompress(garbage, output);
                Assert.IsTrue(written > 0 && written <= output.Length);
            }
            catch (InvalidDataException)
            {
            }
        }
    }

    [TestMethod]
    public void Compress_UnknownType_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => HuffmanCodec.Compress([1, 2, 3], 9));
    }

    private static byte[] CreateInput(string kind, int size)
    {
        var data = new byte[size];
        switch (kind)
        {
            case "text":
                byte[] text = Encoding.ASCII.GetBytes(
                    "The quick brown fox jumps over the lazy dog. MPQ archives store game data in sectors.\r\n");
                for (int i = 0; i < size; i++)
                    data[i] = text[i % text.Length];
                break;

            case "random":
                new Random(size).NextBytes(data);
                break;

            case "zeros":
                break;
        }

        return data;
    }
}
