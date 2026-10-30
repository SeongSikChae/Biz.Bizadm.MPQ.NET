using System.Text.Json;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

namespace Biz.Bizadm.MPQ.NET.Tests.Codecs;

[TestClass]
public sealed class SparseCodecTests
{
    private sealed record SparseVector(string Name, string InputBase64, string CompressedBase64, bool StormLibRoundTrip);

    private static readonly IReadOnlyList<SparseVector> Vectors = JsonSerializer.Deserialize<List<SparseVector>>(
        File.ReadAllText(TestDataPath.Get("sparse-vectors.json")), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    public static IEnumerable<object[]> VectorNames => Vectors.Select(v => new object[] { v.Name });

    /// <summary>Every StormLib SCompCompress output decodes, including the cases StormLib itself rejects.</summary>
    [TestMethod]
    [DynamicData(nameof(VectorNames))]
    public void Decompress_RestoresStormLibOutput(string name)
    {
        var vector = Vectors.Single(v => v.Name == name);
        byte[] input = Convert.FromBase64String(vector.InputBase64);
        byte[] compressed = Convert.FromBase64String(vector.CompressedBase64);
        Assert.AreEqual(0x20, compressed[0], "mask byte");

        var output = new byte[input.Length];
        Assert.AreEqual(input.Length, SparseCodec.Decompress(compressed.AsSpan(1), output));
        CollectionAssert.AreEqual(input, output);
    }

    /// <summary>Where StormLib round-trips, our compressor is byte-identical to SCompCompress.</summary>
    [TestMethod]
    [DynamicData(nameof(VectorNames))]
    public void Compress_MatchesStormLibOrFixesTerminator(string name)
    {
        var vector = Vectors.Single(v => v.Name == name);
        byte[] input = Convert.FromBase64String(vector.InputBase64);
        byte[] stormLib = Convert.FromBase64String(vector.CompressedBase64)[1..];

        byte[] ours = SparseCodec.Compress(input);

        if (vector.StormLibRoundTrip)
        {
            CollectionAssert.AreEqual(stormLib, ours);
        }
        else
        {
            // Same data, only the terminator marker differs: 0xFF (StormLib bug) vs 0x80 | (n - 1).
            Assert.AreEqual(stormLib.Length, ours.Length);
            int marker = ours.Length - 1 - Enumerable.Range(1, 3).First(n => ours[^(n + 1)] == (byte)(0x80 | (n - 1)) && stormLib[^(n + 1)] == 0xFF);
            Assert.AreEqual(0xFF, stormLib[marker]);
            CollectionAssert.AreEqual(stormLib[..marker], ours[..marker]);
            CollectionAssert.AreEqual(stormLib[(marker + 1)..], ours[(marker + 1)..]);
        }

        var output = new byte[input.Length];
        SparseCodec.Decompress(ours, output);
        CollectionAssert.AreEqual(input, output);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    [DataRow(4096)]
    [DataRow(20000)]
    public void RoundTrip(int length)
    {
        var random = new Random(length);
        var data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = random.Next(4) == 0 ? (byte)random.Next(1, 256) : (byte)0;

        byte[] compressed = SparseCodec.Compress(data);
        var output = new byte[length];
        if (length > 0)
            Assert.AreEqual(length, SparseCodec.Decompress(compressed, output));
        CollectionAssert.AreEqual(data, output);
    }

    [TestMethod]
    public void Decompress_ClearsGapWhenInputEndsEarly()
    {
        var output = Enumerable.Repeat((byte)0xAA, 16).ToArray();

        // Size 10, but only 2 literal bytes follow.
        Assert.AreEqual(10, SparseCodec.Decompress([0, 0, 0, 10, 0x81, 1, 2], output));

        CollectionAssert.AreEqual(new byte[] { 1, 2, 0, 0, 0, 0, 0, 0, 0, 0 }, output[..10]);
    }

    [TestMethod]
    public void Decompress_RejectsInvalidInput()
    {
        Assert.ThrowsExactly<InvalidDataException>(() => SparseCodec.Decompress([0, 0, 0], new byte[16]));
        Assert.ThrowsExactly<InvalidDataException>(() => SparseCodec.Decompress([0, 0, 1, 0, 0x7F], new byte[16]));
    }
}
