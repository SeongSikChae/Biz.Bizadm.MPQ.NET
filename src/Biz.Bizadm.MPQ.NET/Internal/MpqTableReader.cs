using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Compression;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Reads, verifies, decrypts and decompresses archive tables (StormLib LoadMpqTable / LoadExtTable).</summary>
internal static class MpqTableReader
{
    public const uint HetSignature = 0x1A544548; // "HET\x1A"
    public const uint BetSignature = 0x1A544542; // "BET\x1A"
    private const int ExtHeaderSize = 12;

    /// <summary>
    /// Loads a hash or block table of <paramref name="tableSize"/> bytes stored in <paramref name="storedSize"/> bytes
    /// (smaller means zlib/other-compressed with a v2 mask). The MD5, when given, covers the stored bytes.
    /// </summary>
    public static byte[] LoadTable(Stream stream, long position, long storedSize, long tableSize, uint key,
        ReadOnlyMemory<byte> md5, bool strict, string tableName)
    {
        if (tableSize > Array.MaxLength)
            throw new InvalidDataException($"The {tableName} is too large.");

        bool compressed = storedSize > 0 && storedSize < tableSize;
        long readSize = compressed ? storedSize : tableSize;
        // Checked before allocating, so a bogus size cannot allocate more than the stream holds.
        // TODO(unit 19): StormLib reads what exists and zero-fills tables that run past the end of the file.
        if (position < 0 || position > stream.Length - readSize)
            throw new InvalidDataException($"The {tableName} extends past the end of the archive.");

        var stored = new byte[readSize];
        stream.ReadExactlyAt(position, stored);
        VerifyMd5(stored, md5, strict, tableName);

        StormCrypto.DecryptBlock(stored.AsSpan(), key);
        if (!compressed)
            return stored;

        var table = new byte[tableSize];
        MpqCompression.Decompress(stored, table, MpqFormatVersion.Version2);
        return table;
    }

    /// <summary>
    /// Loads a HET or BET table: a 12-byte header (signature, version, data size) followed by data encrypted with
    /// <paramref name="key"/> and compressed when the data size exceeds the stored size.
    /// </summary>
    /// <returns>The table data after the 12-byte header.</returns>
    public static byte[] LoadExtTable(Stream stream, long position, long storedSize, uint signature, uint key,
        ReadOnlyMemory<byte> md5, bool strict, string tableName)
    {
        if (storedSize < ExtHeaderSize || storedSize > int.MaxValue)
            throw new InvalidDataException($"Invalid {tableName} size {storedSize}.");
        if (position < 0 || position > stream.Length - storedSize)
            throw new InvalidDataException($"The {tableName} extends past the end of the archive.");

        var stored = new byte[storedSize];
        stream.ReadExactlyAt(position, stored);
        VerifyMd5(stored, md5, strict, tableName);

        if (BinaryPrimitives.ReadUInt32LittleEndian(stored) != signature)
            throw new InvalidDataException($"Invalid {tableName} signature.");
        uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(stored.AsSpan(8));
        if (dataSize > Array.MaxLength)
            throw new InvalidDataException($"Invalid {tableName} data size.");

        var body = stored.AsSpan(ExtHeaderSize);
        StormCrypto.DecryptBlock(body, key);
        if (dataSize + (long)ExtHeaderSize <= storedSize)
            return body[..(int)dataSize].ToArray();

        var data = new byte[dataSize];
        MpqCompression.Decompress(body, data, MpqFormatVersion.Version2);
        return data;
    }

    /// <summary>All-zero MD5 fields mean "not present". Mismatches are errors only in strict mode.</summary>
    public static void VerifyMd5(ReadOnlySpan<byte> data, ReadOnlyMemory<byte> md5, bool strict, string what)
    {
        if (!strict || md5.IsEmpty || md5.Span.IndexOfAnyExcept((byte)0) < 0)
            return;
        if (!MD5.HashData(data).AsSpan().SequenceEqual(md5.Span))
            throw new InvalidDataException($"MD5 of the {what} does not match.");
    }
}
