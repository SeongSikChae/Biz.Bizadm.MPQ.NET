using System.Buffers.Binary;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

namespace Biz.Bizadm.MPQ.NET.Tests.Codecs;

[TestClass]
public sealed class AdpcmCodecTests
{
    private const int SampleRate = 22050;
    private const int Amplitude = 12000;
    private const int MaxSampleError = 1200;
    private const int MaxSilenceError = 2;

    [TestMethod]
    [DataRow(1, 4)]
    [DataRow(1, 5)]
    [DataRow(1, 6)]
    [DataRow(2, 4)]
    [DataRow(2, 5)]
    [DataRow(2, 6)]
    public void CompressThenDecompress_Sine_ReturnsSameLengthAndCloseSamples(int channels, int bitShift)
    {
        byte[] pcm = CreateSine(frames: 4096, channels);

        byte[] compressed = AdpcmCodec.Compress(pcm, channels, bitShift);
        var decoded = new byte[pcm.Length];
        int written = AdpcmCodec.Decompress(compressed, decoded, channels);

        Assert.AreEqual(pcm.Length, written);
        Assert.AreEqual((byte)0, compressed[0]);
        Assert.AreEqual((byte)(bitShift - 1), compressed[1]);
        Assert.IsLessThan(pcm.Length, compressed.Length, "ADPCM should shrink 16-bit PCM.");

        for (int offset = 0; offset < pcm.Length; offset += 2)
        {
            int expected = BinaryPrimitives.ReadInt16LittleEndian(pcm.AsSpan(offset));
            int actual = BinaryPrimitives.ReadInt16LittleEndian(decoded.AsSpan(offset));
            Assert.IsLessThanOrEqualTo(
                MaxSampleError,
                Math.Abs(expected - actual),
                $"Sample at byte {offset}: expected {expected}, got {actual}.");
        }
    }

    [TestMethod]
    [DataRow(1, 5)]
    [DataRow(2, 4)]
    [DataRow(2, 6)]
    public void CompressThenDecompress_Silence_DecodesToSilence(int channels, int bitShift)
    {
        var pcm = new byte[2048 * channels * 2];

        byte[] compressed = AdpcmCodec.Compress(pcm, channels, bitShift);
        var decoded = new byte[pcm.Length];
        int written = AdpcmCodec.Decompress(compressed, decoded, channels);

        Assert.AreEqual(pcm.Length, written);

        // StormLib always adds the (stepSize >> shift) rounding term, so silence decodes to +/-1 noise, not exact zeros.
        for (int offset = 0; offset < decoded.Length; offset += 2)
        {
            int sample = BinaryPrimitives.ReadInt16LittleEndian(decoded.AsSpan(offset));
            Assert.IsLessThanOrEqualTo(MaxSilenceError, Math.Abs(sample), $"Sample at byte {offset} is {sample}.");
        }
    }

    [TestMethod]
    public void Decompress_OutputSmallerThanStream_StopsAtOutputLength()
    {
        byte[] pcm = CreateSine(frames: 512, channels: 2);
        byte[] compressed = AdpcmCodec.Compress(pcm, 2, 5);

        var decoded = new byte[100];
        int written = AdpcmCodec.Decompress(compressed, decoded, 2);

        Assert.AreEqual(100, written);
    }

    [TestMethod]
    [DataRow(new byte[0], 1)]
    [DataRow(new byte[] { 0x00 }, 1)]
    [DataRow(new byte[] { 0x00, 0x04, 0x10 }, 1)]
    [DataRow(new byte[] { 0x00, 0x04, 0x10, 0x00, 0x20 }, 2)]
    public void Decompress_InputShorterThanHeader_ThrowsInvalidData(byte[] input, int channels)
    {
        var output = new byte[64];

        Assert.ThrowsExactly<InvalidDataException>(() => AdpcmCodec.Decompress(input, output, channels));
    }

    private static byte[] CreateSine(int frames, int channels)
    {
        var pcm = new byte[frames * channels * 2];
        for (int frame = 0; frame < frames; frame++)
        {
            for (int channel = 0; channel < channels; channel++)
            {
                // Second channel is phase-shifted so the channels differ.
                double phase = (2 * Math.PI * 440 * frame / SampleRate) + (channel * Math.PI / 3);
                short sample = (short)Math.Round(Amplitude * Math.Sin(phase));
                BinaryPrimitives.WriteInt16LittleEndian(pcm.AsSpan(((frame * channels) + channel) * 2), sample);
            }
        }

        return pcm;
    }
}
