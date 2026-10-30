using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Storm encryption table, string hashing and block encryption, as implemented by StormLib (SBaseCommon.cpp).
/// Names are hashed as UTF-8 bytes; characters are treated as unsigned.
/// </summary>
internal static class StormCrypto
{
    private static readonly uint[] Table = BuildTable();

    public static readonly uint HashTableKey = HashString("(hash table)", MpqHashType.FileKey);
    public static readonly uint BlockTableKey = HashString("(block table)", MpqHashType.FileKey);

    private static uint[] BuildTable()
    {
        var table = new uint[0x500];
        uint seed = 0x00100001;
        for (int i = 0; i < 0x100; i++)
        {
            for (int j = 0, index = i; j < 5; j++, index += 0x100)
            {
                seed = (seed * 125 + 3) % 0x2AAAAB;
                uint high = (seed & 0xFFFF) << 16;
                seed = (seed * 125 + 3) % 0x2AAAAB;
                table[index] = high | (seed & 0xFFFF);
            }
        }
        return table;
    }

    /// <summary>StormLib <c>HashString</c>: ASCII upper case, '/' converted to '\'.</summary>
    public static uint HashString(ReadOnlySpan<char> name, MpqHashType type) => Hash(name, type, convertSlash: true);

    /// <summary>StormLib <c>HashStringSlash</c>: ASCII upper case, '/' kept as is.</summary>
    public static uint HashStringSlash(ReadOnlySpan<char> name, MpqHashType type) => Hash(name, type, convertSlash: false);

    private static uint Hash(ReadOnlySpan<char> name, MpqHashType type, bool convertSlash)
    {
        int max = Encoding.UTF8.GetMaxByteCount(name.Length);
        byte[]? rented = max > 256 ? ArrayPool<byte>.Shared.Rent(max) : null;
        Span<byte> bytes = rented ?? stackalloc byte[256];
        try
        {
            int length = Encoding.UTF8.GetBytes(name, bytes);
            return Hash(bytes[..length], type, convertSlash);
        }
        finally
        {
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static uint Hash(ReadOnlySpan<byte> name, MpqHashType type, bool convertSlash)
    {
        int offset = (int)type << 8;
        uint seed1 = 0x7FED7FED, seed2 = 0xEEEEEEEE;
        foreach (byte b in name)
        {
            uint ch = b switch
            {
                >= (byte)'a' and <= (byte)'z' => (uint)(b - 0x20),
                (byte)'/' when convertSlash => '\\',
                _ => b,
            };
            seed1 = Table[offset + ch] ^ (seed1 + seed2);
            seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
        }
        return seed1;
    }

    public static void DecryptBlock(Span<uint> data, uint key)
    {
        uint seed = 0xEEEEEEEE;
        for (int i = 0; i < data.Length; i++)
        {
            seed += Table[0x400 + (key & 0xFF)];
            uint plain = data[i] ^ (key + seed);
            key = ((~key << 0x15) + 0x11111111) | (key >> 0x0B);
            seed = plain + seed + (seed << 5) + 3;
            data[i] = plain;
        }
    }

    public static void EncryptBlock(Span<uint> data, uint key)
    {
        uint seed = 0xEEEEEEEE;
        for (int i = 0; i < data.Length; i++)
        {
            seed += Table[0x400 + (key & 0xFF)];
            uint plain = data[i];
            data[i] = plain ^ (key + seed);
            key = ((~key << 0x15) + 0x11111111) | (key >> 0x0B);
            seed = plain + seed + (seed << 5) + 3;
        }
    }

    /// <summary>Decrypts whole little-endian DWORDs; a trailing 1-3 bytes stay unencrypted (Storm behavior).</summary>
    public static void DecryptBlock(Span<byte> data, uint key) =>
        DecryptBlock(MemoryMarshal.Cast<byte, uint>(data[..(data.Length & ~3)]), key);

    public static void EncryptBlock(Span<byte> data, uint key) =>
        EncryptBlock(MemoryMarshal.Cast<byte, uint>(data[..(data.Length & ~3)]), key);

    /// <summary>
    /// File key from the plain file name (path removed). With <paramref name="keyV2"/> (MPQ_FILE_KEY_V2, formerly FIX_KEY)
    /// the key is adjusted by the file position relative to the MPQ header and the file size.
    /// </summary>
    public static uint GetFileKey(ReadOnlySpan<char> fileName, long filePosition, uint fileSize, bool keyV2)
    {
        int slash = fileName.LastIndexOfAny('\\', '/');
        uint key = HashString(fileName[(slash + 1)..], MpqHashType.FileKey);
        return keyV2 ? (key + (uint)filePosition) ^ fileSize : key;
    }
}
