using System.Text.Json;
using static Biz.Bizadm.MPQ.NET.FixtureGenerator.StormLib;

namespace Biz.Bizadm.MPQ.NET.FixtureGenerator;

/// <summary>
/// Raw StormLib sparse compression outputs, including the cases StormLib v9.40 cannot decode itself:
/// when one of the last 3 input bytes is nonzero, CompressSparse terminates with 0xFF (a 0x80-byte chunk)
/// followed by fewer bytes, and DecompressSparse rejects it.
/// </summary>
internal static class SparseVectors
{
    public const string FileName = "sparse-vectors.json";

    internal sealed class SparseVector
    {
        public required string Name { get; init; }
        public required string InputBase64 { get; init; }

        /// <summary>SCompCompress output with mask 0x20, including the leading mask byte.</summary>
        public required string CompressedBase64 { get; init; }

        public required bool StormLibRoundTrip { get; init; }
    }

    public static void Generate(string outDir)
    {
        var vectors = new List<SparseVector>
        {
            Create("all-zero-4096", new byte[4096]),
            Create("nonzero-at-100", Single(4096, 100)),
            Create("nonzero-at-3904", Single(4096, 3904)),
            Create("nonzero-at-len-4", Single(4096, 4092)),
            Create("nonzero-at-len-3", Single(4096, 4093)),
            Create("nonzero-at-len-2", Single(4096, 4094)),
            Create("nonzero-at-len-1", Single(4096, 4095)),
            Create("long-nonzero-run", LongRun()),
        };

        File.WriteAllText(Path.Combine(outDir, FileName), JsonSerializer.Serialize(vectors, ExpectedArchive.JsonOptions));
        foreach (var v in vectors)
            Console.WriteLine($"sparse vector {v.Name}: StormLib round trip {(v.StormLibRoundTrip ? "OK" : "FAIL")}");
    }

    private static byte[] Single(int length, int index)
    {
        var data = new byte[length];
        data[index] = 3;
        return data;
    }

    /// <summary>300 nonzero bytes (exercises 0xFF chunks), then 100 zeros.</summary>
    private static byte[] LongRun()
    {
        var data = new byte[400];
        for (int i = 0; i < 300; i++)
            data[i] = (byte)(i % 255 + 1);
        return data;
    }

    private static unsafe SparseVector Create(string name, byte[] input)
    {
        var packed = new byte[input.Length + 64];
        int packedSize = packed.Length;
        fixed (byte* o = packed, i = input)
        {
            if (SCompCompress(o, &packedSize, i, input.Length, 0x20, 0, 0) == 0)
                throw new InvalidOperationException($"SCompCompress({name}) failed.");
        }
        if (packedSize >= input.Length || packed[0] != 0x20)
            throw new InvalidOperationException($"SCompCompress({name}) did not apply sparse compression.");
        Array.Resize(ref packed, packedSize);

        var output = new byte[input.Length];
        int outputSize = output.Length;
        int result;
        fixed (byte* o = output, i = packed)
            result = SCompDecompress(o, &outputSize, i, packedSize);

        return new SparseVector
        {
            Name = name,
            InputBase64 = Convert.ToBase64String(input),
            CompressedBase64 = Convert.ToBase64String(packed),
            StormLibRoundTrip = result != 0 && outputSize == input.Length && output.AsSpan().SequenceEqual(input),
        };
    }
}
