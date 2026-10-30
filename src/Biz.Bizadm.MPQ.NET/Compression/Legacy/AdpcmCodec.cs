// Ported from StormLib adpcm/adpcm.cpp (CompressADPCM / DecompressADPCM).
// StormLib is licensed under the MIT License.
// Copyright (c) 1999-2013 Ladislav Zezula.

using System.Buffers.Binary;

namespace Biz.Bizadm.MPQ.NET.Compression.Legacy;

/// <summary>
/// Blizzard's IMA ADPCM variant used by MPQ compression types 0x40 (mono) and 0x80 (stereo).
/// Samples are 16-bit little-endian PCM; stereo samples are interleaved.
/// </summary>
/// <remarks>
/// Stream layout: byte 0 is zero, byte 1 is the decoder bit shift (CompressionLevel - 1),
/// then one 16-bit initial sample per channel, then one byte per encoded sample.
/// Bytes 0x80 (decrease step index, repeat predicted sample) and 0x81 (increase step index by 8,
/// stay on the same channel) are control markers.
/// </remarks>
internal static class AdpcmCodec
{
    private const int MaxChannelCount = 2;
    private const int InitialStepIndex = 0x2C;
    private const int MaxStepIndex = 0x58;

    private static readonly int[] NextStepTable =
    [
        -1, 0, -1, 4, -1, 2, -1, 6,
        -1, 1, -1, 5, -1, 3, -1, 7,
        -1, 1, -1, 5, -1, 3, -1, 7,
        -1, 2, -1, 4, -1, 6, -1, 8,
    ];

    private static readonly int[] StepSizeTable =
    [
            7,     8,     9,    10,     11,    12,    13,    14,
           16,    17,    19,    21,     23,    25,    28,    31,
           34,    37,    41,    45,     50,    55,    60,    66,
           73,    80,    88,    97,    107,   118,   130,   143,
          157,   173,   190,   209,    230,   253,   279,   307,
          337,   371,   408,   449,    494,   544,   598,   658,
          724,   796,   876,   963,   1060,  1166,  1282,  1411,
         1552,  1707,  1878,  2066,   2272,  2499,  2749,  3024,
         3327,  3660,  4026,  4428,   4871,  5358,  5894,  6484,
         7132,  7845,  8630,  9493,  10442, 11487, 12635, 13899,
        15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
        32767,
    ];

    /// <summary>
    /// Compresses 16-bit PCM like StormLib's <c>CompressADPCM</c>.
    /// </summary>
    /// <param name="input">16-bit little-endian PCM samples (interleaved for stereo).</param>
    /// <param name="channels">1 (mono) or 2 (stereo).</param>
    /// <param name="bitShift">
    /// StormLib's already-mapped <c>CompressionLevel</c> (4, 5 or 6); the stream header stores <paramref name="bitShift"/> - 1.
    /// </param>
    /// <returns>The compressed stream (without the MPQ compression mask byte).</returns>
    /// <remarks>
    /// The output is not size-limited. It matches StormLib's output whenever StormLib's output buffer is
    /// large enough; StormLib silently truncates when its buffer fills.
    /// </remarks>
    public static byte[] Compress(ReadOnlySpan<byte> input, int channels, int bitShift)
    {
        ValidateChannels(channels);
        ArgumentOutOfRangeException.ThrowIfLessThan(bitShift, 4);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(bitShift, 6);

        int compressionLevel = bitShift;
        int headerBitShift = compressionLevel - 1;

        // Worst case: header + per sample one byte plus up to 11 "increase step" markers (0 -> 88 in steps of 8).
        int sampleCount = input.Length / 2;
        var output = new byte[2 + (2 * channels) + (sampleCount * 12)];
        int outPos = 0;
        int inPos = 0;

        Span<short> predictedSamples = stackalloc short[MaxChannelCount];
        Span<short> stepIndexes = stackalloc short[MaxChannelCount];

        // First byte in the output stream contains zero. The second one contains the bit shift.
        output[outPos++] = 0;
        output[outPos++] = (byte)headerBitShift;

        predictedSamples[0] = predictedSamples[1] = 0;
        stepIndexes[0] = stepIndexes[1] = InitialStepIndex;

        // Next, the initial sample value for each channel follows.
        for (int i = 0; i < channels; i++)
        {
            if (!TryReadWordSample(input, ref inPos, out short initialSample))
            {
                return output.AsSpan(0, outPos).ToArray();
            }

            predictedSamples[i] = initialSample;
            BinaryPrimitives.WriteInt16LittleEndian(output.AsSpan(outPos), initialSample);
            outPos += 2;
        }

        int channelIndex = channels - 1;

        while (TryReadWordSample(input, ref inPos, out short inputSample))
        {
            int encodedSample = 0;

            // If we have two channels, flip the channel index.
            channelIndex = (channelIndex + 1) % channels;

            // Difference from the previous sample; a negative difference sets the sign bit.
            int absDifference = inputSample - predictedSamples[channelIndex];
            if (absDifference < 0)
            {
                absDifference = -absDifference;
                encodedSample |= 0x40;
            }

            int stepSize = StepSizeTable[stepIndexes[channelIndex]];
            if (absDifference < (stepSize >> compressionLevel))
            {
                // Difference too small: write the "decrease step index" marker.
                if (stepIndexes[channelIndex] != 0)
                {
                    stepIndexes[channelIndex]--;
                }

                output[outPos++] = 0x80;
            }
            else
            {
                // Difference too large: write "increase step index" markers.
                while (absDifference > (stepSize << 1))
                {
                    if (stepIndexes[channelIndex] >= MaxStepIndex)
                    {
                        break;
                    }

                    stepIndexes[channelIndex] += 8;
                    if (stepIndexes[channelIndex] > MaxStepIndex)
                    {
                        stepIndexes[channelIndex] = MaxStepIndex;
                    }

                    stepSize = StepSizeTable[stepIndexes[channelIndex]];
                    output[outPos++] = 0x81;
                }

                int maxBitMask = 1 << (headerBitShift - 1);
                maxBitMask = maxBitMask > 0x20 ? 0x20 : maxBitMask;
                int difference = stepSize >> headerBitShift;
                int totalStepSize = 0;

                for (int bitVal = 0x01; bitVal <= maxBitMask; bitVal <<= 1)
                {
                    if ((totalStepSize + stepSize) <= absDifference)
                    {
                        totalStepSize += stepSize;
                        encodedSample |= bitVal;
                    }

                    stepSize >>= 1;
                }

                predictedSamples[channelIndex] = (short)UpdatePredictedSample(
                    predictedSamples[channelIndex], encodedSample, difference + totalStepSize);

                output[outPos++] = (byte)encodedSample;

                stepIndexes[channelIndex] = GetNextStepIndex(stepIndexes[channelIndex], encodedSample);
            }
        }

        return output.AsSpan(0, outPos).ToArray();
    }

    /// <summary>
    /// Decompresses an ADPCM stream like StormLib's <c>DecompressADPCM</c>.
    /// </summary>
    /// <param name="input">The compressed stream (without the MPQ compression mask byte).</param>
    /// <param name="output">Destination for 16-bit PCM; its length is the maximum number of bytes to write.</param>
    /// <param name="channels">1 (mono) or 2 (stereo).</param>
    /// <returns>The number of bytes written to <paramref name="output"/>.</returns>
    /// <exception cref="InvalidDataException">The input is shorter than the stream header.</exception>
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output, int channels)
    {
        ValidateChannels(channels);

        int headerLength = 2 + (2 * channels);
        if (input.Length < headerLength)
        {
            throw new InvalidDataException(
                $"ADPCM stream is {input.Length} bytes; the {channels}-channel header needs {headerLength} bytes.");
        }

        Span<short> predictedSamples = stackalloc short[MaxChannelCount];
        Span<short> stepIndexes = stackalloc short[MaxChannelCount];
        predictedSamples[0] = predictedSamples[1] = 0;
        stepIndexes[0] = stepIndexes[1] = InitialStepIndex;

        // The first byte is always zero, the second one contains the bit shift (compression level - 1).
        int bitShift = input[1];
        int inPos = 2;
        int outPos = 0;

        // Next, the initial sample value for each channel follows.
        for (int i = 0; i < channels; i++)
        {
            TryReadWordSample(input, ref inPos, out short initialSample);
            predictedSamples[i] = initialSample;

            if (!TryWriteWordSample(output, ref outPos, initialSample))
            {
                return outPos;
            }
        }

        int channelIndex = channels - 1;

        while (inPos < input.Length)
        {
            byte encodedSample = input[inPos++];

            // If we have two channels, flip the channel index.
            channelIndex = (channelIndex + 1) % channels;

            if (encodedSample == 0x80)
            {
                if (stepIndexes[channelIndex] != 0)
                {
                    stepIndexes[channelIndex]--;
                }

                if (!TryWriteWordSample(output, ref outPos, predictedSamples[channelIndex]))
                {
                    return outPos;
                }
            }
            else if (encodedSample == 0x81)
            {
                stepIndexes[channelIndex] += 8;
                if (stepIndexes[channelIndex] > MaxStepIndex)
                {
                    stepIndexes[channelIndex] = MaxStepIndex;
                }

                // Next pass, keep going on the same channel.
                channelIndex = (channelIndex + 1) % channels;
            }
            else
            {
                int stepIndex = stepIndexes[channelIndex];
                int stepSize = StepSizeTable[stepIndex];

                predictedSamples[channelIndex] = (short)DecodeSample(
                    predictedSamples[channelIndex], encodedSample, stepSize, stepSize >> bitShift);

                if (!TryWriteWordSample(output, ref outPos, predictedSamples[channelIndex]))
                {
                    break;
                }

                stepIndexes[channelIndex] = GetNextStepIndex(stepIndex, encodedSample);
            }
        }

        return outPos;
    }

    private static void ValidateChannels(int channels)
    {
        if (channels is < 1 or > MaxChannelCount)
        {
            throw new ArgumentOutOfRangeException(nameof(channels), channels, "ADPCM supports 1 or 2 channels.");
        }
    }

    private static bool TryReadWordSample(ReadOnlySpan<byte> input, ref int position, out short sample)
    {
        if (input.Length - position < sizeof(short))
        {
            sample = 0;
            return false;
        }

        sample = BinaryPrimitives.ReadInt16LittleEndian(input[position..]);
        position += sizeof(short);
        return true;
    }

    private static bool TryWriteWordSample(Span<byte> output, ref int position, short sample)
    {
        if (output.Length - position < sizeof(short))
        {
            return false;
        }

        BinaryPrimitives.WriteInt16LittleEndian(output[position..], sample);
        position += sizeof(short);
        return true;
    }

    private static short GetNextStepIndex(int stepIndex, int encodedSample)
    {
        stepIndex += NextStepTable[encodedSample & 0x1F];

        // Don't let the step index overflow.
        if (stepIndex < 0)
        {
            stepIndex = 0;
        }
        else if (stepIndex > 88)
        {
            stepIndex = 88;
        }

        return (short)stepIndex;
    }

    private static int UpdatePredictedSample(int predictedSample, int encodedSample, int difference)
    {
        // Is the sign bit set?
        if ((encodedSample & 0x40) != 0)
        {
            predictedSample -= difference;
            if (predictedSample <= -32768)
            {
                predictedSample = -32768;
            }
        }
        else
        {
            predictedSample += difference;
            if (predictedSample >= 32767)
            {
                predictedSample = 32767;
            }
        }

        return predictedSample;
    }

    private static int DecodeSample(int predictedSample, int encodedSample, int stepSize, int difference)
    {
        if ((encodedSample & 0x01) != 0)
        {
            difference += stepSize >> 0;
        }

        if ((encodedSample & 0x02) != 0)
        {
            difference += stepSize >> 1;
        }

        if ((encodedSample & 0x04) != 0)
        {
            difference += stepSize >> 2;
        }

        if ((encodedSample & 0x08) != 0)
        {
            difference += stepSize >> 3;
        }

        if ((encodedSample & 0x10) != 0)
        {
            difference += stepSize >> 4;
        }

        if ((encodedSample & 0x20) != 0)
        {
            difference += stepSize >> 5;
        }

        return UpdatePredictedSample(predictedSample, encodedSample, difference);
    }
}
