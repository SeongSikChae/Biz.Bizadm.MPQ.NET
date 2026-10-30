using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class HetBetTests
{
    public static IEnumerable<object[]> HetArchives => [["v3-lzma.mpq"], ["v4-mixed.mpq"]];

    /// <summary>lookup3.c driver5 reference values for hashlittle2.</summary>
    [TestMethod]
    [DataRow("", 0u, 0u, 0xDEADBEEFu, 0xDEADBEEFu)]
    [DataRow("", 0u, 0xDEADBEEFu, 0xBD5B7DDEu, 0xDEADBEEFu)]
    [DataRow("", 0xDEADBEEFu, 0xDEADBEEFu, 0x9C093CCDu, 0xBD5B7DDEu)]
    [DataRow("Four score and seven years ago", 0u, 0u, 0x17770551u, 0xCE7226E6u)]
    [DataRow("Four score and seven years ago", 0u, 1u, 0xE3607CAEu, 0xBD371DE4u)]
    [DataRow("Four score and seven years ago", 1u, 0u, 0xCD628161u, 0x6CBEA4B3u)]
    public void HashLittle2_MatchesLookup3(string text, uint c, uint b, uint expectedC, uint expectedB)
    {
        JenkinsHash.HashLittle2(Encoding.ASCII.GetBytes(text), ref c, ref b);
        Assert.AreEqual(expectedC, c, "pc");
        Assert.AreEqual(expectedB, b, "pb");
    }

    [TestMethod]
    public void HashFileName_NormalizesCaseAndSlash()
    {
        ulong expected = JenkinsHash.HashFileName(@"data\random.bin");
        Assert.AreEqual(expected, JenkinsHash.HashFileName(@"DATA\Random.BIN"));
        Assert.AreEqual(expected, JenkinsHash.HashFileName("data/random.bin"));
    }

    /// <summary>Lookups that only use the HET table (no classic hash table) find every file.</summary>
    [TestMethod]
    [DynamicData(nameof(HetArchives))]
    public void Het_FindsEveryFileWithoutHashTable(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        var table = Load(File.ReadAllBytes(TestDataPath.Get(archive)));
        Assert.IsNotNull(table.Het);
        var hetOnly = new MpqFileTable([], table.Entries.ToArray(), table.Het);

        foreach (var file in expected.Files)
        {
            var viaHash = table.Find(file.Name);
            Assert.IsNotNull(viaHash, file.Name);
            Assert.AreSame(viaHash, hetOnly.Find(file.Name), file.Name);
            Assert.AreEqual(table.Het.HashName(file.Name), viaHash.NameHash, file.Name);
        }
        Assert.IsNull(hetOnly.Find("missing.txt"));
    }

    /// <summary>With the hash table size zeroed, the file table comes from the BET table alone and still reads like StormLib.</summary>
    [TestMethod]
    [DynamicData(nameof(HetArchives))]
    public void Bet_BuildsSameFileTableAsBlockTable(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        byte[] data = File.ReadAllBytes(TestDataPath.Get(archive));
        var classic = Load(data);

        byte[] betOnly = (byte[])data.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(betOnly.AsSpan(0x18), 0); // dwHashTableSize
        var bet = Load(betOnly);

        Assert.AreEqual(0, bet.HashEntries.Count);
        foreach (var file in expected.Files)
        {
            var a = classic.Find(file.Name)!;
            var b = bet.Find(file.Name);
            Assert.IsNotNull(b, file.Name);
            Assert.AreEqual(a.FilePosition, b.FilePosition, file.Name);
            Assert.AreEqual(a.FileSize, b.FileSize, file.Name);
            Assert.AreEqual(a.CompressedSize, b.CompressedSize, file.Name);
            Assert.AreEqual(a.Flags, b.Flags, file.Name);
        }

        using var mpq = MpqArchive.Open(new MemoryStream(betOnly, writable: false));
        foreach (var file in expected.Files)
        {
            using var stream = mpq.OpenFile(file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(stream)), file.Name);
        }
    }

    [TestMethod]
    public void V4_StrictOpenVerifiesMd5s()
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v4-mixed.mpq"));
        using (var mpq = MpqArchive.Open(new MemoryStream(data, writable: false), options: new MpqOpenOptions { Strict = true }))
            Assert.IsTrue(mpq.Contains(@"sound\stereo.wav"));
    }

    /// <summary>A wrong MD5 (header 0x70 block, 0x80 hash, 0xA0 BET, 0xB0 HET, 0xC0 header) fails only in strict mode.</summary>
    [TestMethod]
    [DataRow(0x70)]
    [DataRow(0x80)]
    [DataRow(0xA0)]
    [DataRow(0xB0)]
    [DataRow(0xC0)]
    public void V4_Md5MismatchThrowsOnlyWhenStrict(int md5Offset)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v4-mixed.mpq"));
        data[md5Offset] ^= 0xFF;
        if (md5Offset != 0xC0)
            FixHeaderMd5(data);

        using (var lenient = MpqArchive.Open(new MemoryStream(data, writable: false)))
            Assert.IsTrue(lenient.Contains(@"sound\stereo.wav"));
        Assert.ThrowsExactly<InvalidDataException>(() =>
            MpqArchive.Open(new MemoryStream(data, writable: false), options: new MpqOpenOptions { Strict = true }));
    }

    /// <summary>
    /// v2 tables may be compressed: the stored hash table size is the gap to the block table (StormLib LoadMpqTable).
    /// The fixture's hash table is re-stored as encrypted zlib data and the block table moved right after it.
    /// </summary>
    [TestMethod]
    public void V2_ReadsCompressedHashTable()
    {
        var expected = ExpectedArchive.Load("v2-bzip2.mpq");
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v2-bzip2.mpq"));
        using var probe = new MemoryStream(data);
        var (header, _, _) = MpqHeaderReader.Find(probe);
        int hashPos = (int)header.HashTablePosition, blockPos = (int)header.BlockTablePosition;
        int hashSize = (int)header.HashTableSize * 16, blockSize = (int)header.BlockTableSize * 16;
        Assert.AreEqual(hashPos + hashSize, blockPos, "fixture layout: block table follows hash table");

        byte[] hash = data.AsSpan(hashPos, hashSize).ToArray();
        StormCrypto.DecryptBlock(hash.AsSpan(), StormCrypto.HashTableKey);
        byte[] packed = [(byte)MpqCompressionType.Zlib, .. ZlibCompress(hash)];
        Assert.IsTrue(packed.Length < hashSize);
        StormCrypto.EncryptBlock(packed.AsSpan(), StormCrypto.HashTableKey);

        byte[] rebuilt = [.. data.AsSpan(0, hashPos), .. packed, .. data.AsSpan(blockPos, blockSize), .. data.AsSpan(blockPos + blockSize)];
        BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(0x14), (uint)(hashPos + packed.Length)); // dwBlockTablePos
        BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(0x08), (uint)rebuilt.Length);             // dwArchiveSize

        using var mpq = MpqArchive.Open(new MemoryStream(rebuilt, writable: false));
        foreach (var file in expected.Files)
        {
            using var stream = mpq.OpenFile(file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(stream)), file.Name);
        }
    }

    /// <summary>StormLib opens an archive without hash and HET tables as an empty archive.</summary>
    [TestMethod]
    public void Open_EmptyArchiveWithoutTables()
    {
        var data = new byte[0x20];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x1A51504D);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0x20);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0E), 3);

        using var mpq = MpqArchive.Open(new MemoryStream(data, writable: false));
        Assert.AreEqual(0, mpq.Entries.Count());
        Assert.IsFalse(mpq.Contains("readme.txt"));
    }

    /// <summary>StormLib treats an unknown format version as v1 (common in protected maps).</summary>
    [TestMethod]
    public void Open_UnknownFormatVersionAsV1()
    {
        var expected = ExpectedArchive.Load("v1-zlib.mpq");
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0C), 7);

        using var mpq = MpqArchive.Open(new MemoryStream(data, writable: false));
        Assert.AreEqual(MpqFormatVersion.Version1, mpq.Header.FormatVersion);
        foreach (var file in expected.Files)
        {
            using var stream = mpq.OpenFile(file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(stream)), file.Name);
        }
    }

    /// <summary>Malformed HET/BET values must surface as InvalidDataException, not as index or overflow errors.</summary>
    [TestMethod]
    public void Het_LargeIndexIsNotTreatedAsNegative()
    {
        // HET with one slot whose 32-bit index is 0xFFFFFFFF.
        var het = new byte[32 + 1 + 4];
        BinaryPrimitives.WriteUInt32LittleEndian(het, (uint)het.Length); // table size
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(4), 1);      // entry count
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(8), 1);      // total count
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(12), 64);    // name hash bits
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(16), 32);    // index size total
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(24), 32);    // index size
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(28), 4);     // index table size
        het[32] = 0x80;
        BinaryPrimitives.WriteUInt32LittleEndian(het.AsSpan(33), 0xFFFFFFFF);
        var table = HetTable.Parse(het);

        Assert.IsNull(table.FindIndex(0x8000000000000000, [new MpqFileEntry()]));

        var bet = new byte[76];
        BinaryPrimitives.WriteUInt32LittleEndian(bet.AsSpan(14 * 4), 0xFFFFFFFF); // total NameHash2 bits
        BinaryPrimitives.WriteUInt32LittleEndian(bet.AsSpan(16 * 4), 56);         // NameHash2 bits
        BinaryPrimitives.WriteUInt32LittleEndian(bet.AsSpan(4), 1);               // entry count
        Assert.ThrowsExactly<InvalidDataException>(() => BetTable.Apply(bet, table, [new MpqFileEntry()]));
    }

    [TestMethod]
    public void Het_RejectsCorruptTable()
    {
        Assert.ThrowsExactly<InvalidDataException>(() => HetTable.Parse(new byte[8]));
        var header = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 1000); // table size larger than the data
        Assert.ThrowsExactly<InvalidDataException>(() => HetTable.Parse(header));
    }

    private static MpqFileTable Load(byte[] data)
    {
        using var stream = new MemoryStream(data, writable: false);
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        return MpqFileTable.Load(stream, header, headerOffset);
    }

    private static void FixHeaderMd5(byte[] data) => MD5.HashData(data.AsSpan(0, 0xC0)).CopyTo(data, 0xC0);

    private static byte[] ZlibCompress(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(data);
        return ms.ToArray();
    }
}
