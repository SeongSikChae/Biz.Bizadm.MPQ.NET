using System.Buffers;
using System.Numerics;
using System.Text;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// 64-bit file name hash for HET/BET tables (StormLib HashStringJenkins): Bob Jenkins' lookup3 hashlittle2
/// over the name converted with AsciiToLowerTable (ASCII lower case, '/' to '\'), at most 0x108 bytes.
/// </summary>
internal static class JenkinsHash
{
    private const int MaxNameLength = 0x108;

    public static ulong HashFileName(ReadOnlySpan<char> name)
    {
        int max = Encoding.UTF8.GetMaxByteCount(name.Length);
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(max, MaxNameLength));
        try
        {
            int length = Math.Min(Encoding.UTF8.GetBytes(name, rented), MaxNameLength);
            for (int i = 0; i < length; i++)
            {
                byte b = rented[i];
                rented[i] = b switch
                {
                    >= (byte)'A' and <= (byte)'Z' => (byte)(b + 0x20),
                    (byte)'/' => (byte)'\\',
                    _ => b,
                };
            }

            uint primary = 1, secondary = 2;
            HashLittle2(rented.AsSpan(0, length), ref secondary, ref primary);
            return ((ulong)primary << 32) | secondary;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>lookup3.c hashlittle2 (byte-wise variant, identical results on any alignment).</summary>
    public static void HashLittle2(ReadOnlySpan<byte> key, ref uint pc, ref uint pb)
    {
        uint a, b, c;
        a = b = c = 0xDEADBEEF + (uint)key.Length + pc;
        c += pb;

        while (key.Length > 12)
        {
            a += Word(key, 0);
            b += Word(key, 4);
            c += Word(key, 8);
            Mix(ref a, ref b, ref c);
            key = key[12..];
        }

        if (key.Length == 0)
        {
            pc = c;
            pb = b;
            return;
        }

        Span<byte> tail = stackalloc byte[12];
        tail.Clear();
        key.CopyTo(tail);
        a += Word(tail, 0);
        b += Word(tail, 4);
        c += Word(tail, 8);
        Final(ref a, ref b, ref c);
        pc = c;
        pb = b;
    }

    private static uint Word(ReadOnlySpan<byte> k, int offset) =>
        k[offset] | ((uint)k[offset + 1] << 8) | ((uint)k[offset + 2] << 16) | ((uint)k[offset + 3] << 24);

    private static void Mix(ref uint a, ref uint b, ref uint c)
    {
        a -= c; a ^= BitOperations.RotateLeft(c, 4); c += b;
        b -= a; b ^= BitOperations.RotateLeft(a, 6); a += c;
        c -= b; c ^= BitOperations.RotateLeft(b, 8); b += a;
        a -= c; a ^= BitOperations.RotateLeft(c, 16); c += b;
        b -= a; b ^= BitOperations.RotateLeft(a, 19); a += c;
        c -= b; c ^= BitOperations.RotateLeft(b, 4); b += a;
    }

    private static void Final(ref uint a, ref uint b, ref uint c)
    {
        c ^= b; c -= BitOperations.RotateLeft(b, 14);
        a ^= c; a -= BitOperations.RotateLeft(c, 11);
        b ^= a; b -= BitOperations.RotateLeft(a, 25);
        c ^= b; c -= BitOperations.RotateLeft(b, 16);
        a ^= c; a -= BitOperations.RotateLeft(c, 4);
        b ^= a; b -= BitOperations.RotateLeft(a, 14);
        c ^= b; c -= BitOperations.RotateLeft(b, 24);
    }
}
