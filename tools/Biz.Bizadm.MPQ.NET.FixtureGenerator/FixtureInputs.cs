using System.Text;

namespace Biz.Bizadm.MPQ.NET.FixtureGenerator;

/// <summary>Deterministic input files used to build the fixtures.</summary>
internal static class FixtureInputs
{
    public const string Readme = "readme.txt";
    public const string Random = @"data\random.bin";
    public const string Zeros = @"data\zeros.bin";
    public const string Small = @"data\small.txt";
    public const string Empty = @"data\empty.txt";
    public const string StereoWave = @"sound\stereo.wav";
    public const string MonoWave = @"sound\mono.wav";
    public const string PatchedBefore = @"data\patched.txt";

    public static readonly byte[] PatchedAfter = Encoding.ASCII.GetBytes("Patched file, version 2. The content was replaced by a COPY patch.\r\n");

    public static IReadOnlyDictionary<string, byte[]> Create()
    {
        var text = new StringBuilder();
        for (int i = 0; i < 300; i++)
            text.Append($"Line {i:D4}: The quick brown fox jumps over the lazy dog.\r\n");

        var random = new byte[20000];
        new Random(1234).NextBytes(random);

        // Keep the last 3 bytes of every 4 KB sector zero: StormLib v9.40 CompressSparse writes an invalid
        // terminator when they are not, and its own DecompressSparse then rejects the sector (see SparseVectors).
        var zeros = new byte[16384];
        zeros[100] = 1;
        zeros[8000] = 2;
        zeros[16379] = 3;

        return new Dictionary<string, byte[]>
        {
            [Readme] = Encoding.ASCII.GetBytes(text.ToString()),
            [Random] = random,
            [Zeros] = zeros,
            [Small] = "abc"u8.ToArray(),
            [Empty] = [],
            [StereoWave] = CreateWave(channels: 2),
            [MonoWave] = CreateWave(channels: 1),
            [PatchedBefore] = Encoding.ASCII.GetBytes("Original file, version 1.\r\n"),
        };
    }

    /// <summary>16-bit PCM, 22050 Hz, 0.5 s, 440 Hz sine.</summary>
    private static byte[] CreateWave(int channels)
    {
        const int sampleRate = 22050;
        int samples = sampleRate / 2;
        int dataSize = samples * channels * 2;

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("RIFF"u8);
        w.Write(36 + dataSize);
        w.Write("WAVEfmt "u8);
        w.Write(16);
        w.Write((short)1);
        w.Write((short)channels);
        w.Write(sampleRate);
        w.Write(sampleRate * channels * 2);
        w.Write((short)(channels * 2));
        w.Write((short)16);
        w.Write("data"u8);
        w.Write(dataSize);
        for (int i = 0; i < samples; i++)
        {
            short value = (short)(Math.Sin(2 * Math.PI * 440 * i / sampleRate) * 12000);
            for (int c = 0; c < channels; c++)
                w.Write(c == 0 ? value : (short)(value / 2));
        }
        w.Flush();
        return ms.ToArray();
    }
}
