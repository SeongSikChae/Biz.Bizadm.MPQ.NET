using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Json;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class StormCryptoTests
{
    [TestMethod]
    public void TableKeys_MatchKnownValues()
    {
        Assert.AreEqual(0xC3AF3770u, StormCrypto.HashTableKey);
        Assert.AreEqual(0xEC83B3A3u, StormCrypto.BlockTableKey);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public void HashString_IgnoresAsciiCase(int hashType)
    {
        var type = (MpqHashType)hashType;
        Assert.AreEqual(StormCrypto.HashString(@"data\readme.txt", type), StormCrypto.HashString(@"DATA\README.TXT", type));
        Assert.AreEqual(StormCrypto.HashStringSlash(@"data\readme.txt", type), StormCrypto.HashStringSlash(@"Data\ReadMe.Txt", type));
    }

    [TestMethod]
    public void HashString_ConvertsSlash_HashStringSlashKeepsIt()
    {
        Assert.AreEqual(StormCrypto.HashString(@"data\a.bin", MpqHashType.NameA), StormCrypto.HashString("data/a.bin", MpqHashType.NameA));
        Assert.AreEqual(StormCrypto.HashString(@"data\a.bin", MpqHashType.NameA), StormCrypto.HashStringSlash(@"data\a.bin", MpqHashType.NameA));
        Assert.AreNotEqual(StormCrypto.HashStringSlash(@"data\a.bin", MpqHashType.NameA), StormCrypto.HashStringSlash("data/a.bin", MpqHashType.NameA));
    }

    [TestMethod]
    public void HashString_HandlesLongNonAsciiNames()
    {
        string name = string.Concat(Enumerable.Repeat("데이터\\", 60)) + "파일.txt";
        Assert.AreEqual(StormCrypto.HashString(name, MpqHashType.NameB), StormCrypto.HashString(name.ToUpperInvariant().Replace("TXT", "txt"), MpqHashType.NameB));
    }

    [TestMethod]
    public void EncryptDecrypt_RoundTrip()
    {
        uint[] original = Enumerable.Range(0, 257).Select(i => (uint)(i * 2654435761u)).ToArray();
        uint[] data = (uint[])original.Clone();

        StormCrypto.EncryptBlock(data, 0x12345678);
        CollectionAssert.AreNotEqual(original, data);
        StormCrypto.DecryptBlock(data, 0x12345678);
        CollectionAssert.AreEqual(original, data);
    }

    [TestMethod]
    public void EncryptBytes_LeavesTrailingBytesUnencrypted()
    {
        byte[] original = Enumerable.Range(1, 11).Select(i => (byte)i).ToArray();
        byte[] data = (byte[])original.Clone();

        StormCrypto.EncryptBlock(data.AsSpan(), 0xCAFEBABE);
        CollectionAssert.AreEqual(original[8..], data[8..]);
        CollectionAssert.AreNotEqual(original[..8], data[..8]);
        StormCrypto.DecryptBlock(data.AsSpan(), 0xCAFEBABE);
        CollectionAssert.AreEqual(original, data);
    }

    [TestMethod]
    public void GetFileKey_UsesPlainName()
    {
        uint plain = StormCrypto.HashString("random.bin", MpqHashType.FileKey);
        Assert.AreEqual(plain, StormCrypto.GetFileKey(@"data\random.bin", 0, 0, keyV2: false));
        Assert.AreEqual(plain, StormCrypto.GetFileKey("data/random.bin", 0, 0, keyV2: false));
        Assert.AreEqual((plain + 0x1234u) ^ 20000u, StormCrypto.GetFileKey(@"data\random.bin", 0x1234, 20000, keyV2: true));
    }

    /// <summary>Decrypts the StormLib-written hash and block tables of v1-zlib.mpq and finds readme.txt.</summary>
    [TestMethod]
    public void DecryptTables_FindsFileInStormLibArchive()
    {
        byte[] mpq = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        var (hash, block) = ReadTables(mpq);

        uint index = StormCrypto.HashStringSlash("readme.txt", MpqHashType.TableOffset);
        uint a = StormCrypto.HashStringSlash("readme.txt", MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash("readme.txt", MpqHashType.NameB);
        int entries = hash.Length / 4;
        int? blockIndex = null;
        for (int n = 0, i = (int)(index & (uint)(entries - 1)); n < entries; n++, i = (i + 1) & (entries - 1))
        {
            if (hash[i * 4 + 3] == 0xFFFFFFFF)
                break;
            if (hash[i * 4] == a && hash[i * 4 + 1] == b)
            {
                blockIndex = (int)hash[i * 4 + 3];
                break;
            }
        }

        Assert.IsNotNull(blockIndex, "readme.txt not found in the decrypted hash table.");
        Assert.AreEqual(ExpectedSize("v1-zlib.mpq", "readme.txt"), (int)block[blockIndex.Value * 4 + 2]);
        Assert.AreNotEqual(0u, block[blockIndex.Value * 4 + 3] & 0x80000000u, "MPQ_FILE_EXISTS not set.");
    }

    /// <summary>The decrypted sector offset table of an encrypted file starts with the table size.</summary>
    [TestMethod]
    [DataRow("readme.txt", false)]
    [DataRow(@"data\random.bin", true)]
    public void GetFileKey_DecryptsSectorOffsetTable(string name, bool keyV2)
    {
        byte[] mpq = File.ReadAllBytes(TestDataPath.Get("v1-encrypted.mpq"));
        var (hash, block) = ReadTables(mpq);
        int blockIndex = FindBlock(hash, name);

        uint filePos = block[blockIndex * 4];
        uint fileSize = block[blockIndex * 4 + 2];
        uint flags = block[blockIndex * 4 + 3];
        Assert.AreEqual(keyV2, (flags & 0x00020000u) != 0);

        int sectors = (int)((fileSize + 0xFFF) / 0x1000);
        uint[] offsets = MemoryMarshal.Cast<byte, uint>(mpq.AsSpan((int)filePos, (sectors + 1) * 4)).ToArray();
        StormCrypto.DecryptBlock(offsets, StormCrypto.GetFileKey(name, filePos, fileSize, keyV2) - 1);

        Assert.AreEqual((uint)((sectors + 1) * 4), offsets[0]);
        Assert.AreEqual(block[blockIndex * 4 + 1], offsets[^1]);
    }

    private static (uint[] Hash, uint[] Block) ReadTables(byte[] mpq)
    {
        uint hashPos = BinaryPrimitives.ReadUInt32LittleEndian(mpq.AsSpan(0x10));
        uint blockPos = BinaryPrimitives.ReadUInt32LittleEndian(mpq.AsSpan(0x14));
        int hashCount = BinaryPrimitives.ReadInt32LittleEndian(mpq.AsSpan(0x18));
        int blockCount = BinaryPrimitives.ReadInt32LittleEndian(mpq.AsSpan(0x1C));

        uint[] hash = MemoryMarshal.Cast<byte, uint>(mpq.AsSpan((int)hashPos, hashCount * 16)).ToArray();
        uint[] block = MemoryMarshal.Cast<byte, uint>(mpq.AsSpan((int)blockPos, blockCount * 16)).ToArray();
        StormCrypto.DecryptBlock(hash, StormCrypto.HashTableKey);
        StormCrypto.DecryptBlock(block, StormCrypto.BlockTableKey);
        return (hash, block);
    }

    private static int FindBlock(uint[] hash, string name)
    {
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        for (int i = 0; i < hash.Length / 4; i++)
            if (hash[i * 4] == a && hash[i * 4 + 1] == b && hash[i * 4 + 3] < 0xFFFFFFFE)
                return (int)hash[i * 4 + 3];
        throw new AssertFailedException($"{name} not found.");
    }

    private static int ExpectedSize(string archive, string name)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(TestDataPath.Get(archive + ".expected.json")));
        return doc.RootElement.GetProperty("files").EnumerateArray()
            .First(f => f.GetProperty("name").GetString() == name)
            .GetProperty("size").GetInt32();
    }
}
