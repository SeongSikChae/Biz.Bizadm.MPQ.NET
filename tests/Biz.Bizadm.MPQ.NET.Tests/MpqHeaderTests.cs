using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqHeaderTests
{
    public static IEnumerable<object[]> Archives =>
    [
        ["v1-zlib.mpq"], ["v1-pkware.mpq"], ["v1-encrypted.mpq"], ["v1-sector-options.mpq"], ["v1-legacy-masks.mpq"],
        ["v1-weak-signed.mpq"], ["v2-bzip2.mpq"], ["sc2-userdata.SC2Replay"], ["patch-base.mpq"], ["patch-1.mpq"],
        ["v3-lzma.mpq"], ["v4-mixed.mpq"],
    ];

    [TestMethod]
    [DynamicData(nameof(Archives))]
    public void Find_ReadsHeaderOfStormLibArchive(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        using var stream = File.OpenRead(TestDataPath.Get(archive));

        var (header, userData, headerOffset) = MpqHeaderReader.Find(stream);

        var version = (MpqFormatVersion)(expected.FormatVersion - 1);
        Assert.AreEqual(version, header.FormatVersion);
        Assert.AreEqual(expected.SectorSize, header.SectorSize);
        Assert.AreEqual(expected.UserData?.HeaderOffset ?? 0, (int)headerOffset);
        Assert.AreEqual(expected.UserData is not null, userData is not null);
        Assert.AreEqual(version switch
        {
            MpqFormatVersion.Version1 => 0x20u,
            MpqFormatVersion.Version2 => 0x2Cu,
            MpqFormatVersion.Version3 => 0x44u,
            _ => 0xD0u,
        }, header.HeaderSize);
        Assert.AreEqual(stream.Length - headerOffset, header.ArchiveSize);
    }

    /// <summary>The hash table position (relative to the MPQ header) leads to a table that contains "(listfile)".</summary>
    [TestMethod]
    [DynamicData(nameof(Archives))]
    public void Find_HashTablePositionPointsToHashTable(string archive)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get(archive));
        using var stream = new MemoryStream(data);
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);

        int start = (int)(headerOffset + header.HashTablePosition);
        uint[] hash = MemoryMarshal.Cast<byte, uint>(data.AsSpan(start, (int)header.HashTableSize * 16)).ToArray();
        StormCrypto.DecryptBlock(hash, StormCrypto.HashTableKey);

        uint a = StormCrypto.HashStringSlash("(listfile)", MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash("(listfile)", MpqHashType.NameB);
        bool found = Enumerable.Range(0, hash.Length / 4).Any(i => hash[i * 4] == a && hash[i * 4 + 1] == b && hash[i * 4 + 3] < header.BlockTableSize);
        Assert.IsTrue(found, "(listfile) not found in the hash table.");
    }

    [TestMethod]
    [DynamicData(nameof(Archives))]
    public void Find_ReadsVersionSpecificFields(string archive)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get(archive));
        using var stream = new MemoryStream(data);
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);

        if (header.FormatVersion >= MpqFormatVersion.Version3)
        {
            Assert.AreEqual(0x1A544548u, SignatureAt(data, headerOffset + header.HetTablePosition), "HET\\x1A");
            Assert.AreEqual(0x1A544542u, SignatureAt(data, headerOffset + header.BetTablePosition), "BET\\x1A");
        }
        else
        {
            Assert.AreEqual(0, header.HetTablePosition);
            Assert.AreEqual(0, header.BetTablePosition);
        }

        if (header.FormatVersion == MpqFormatVersion.Version4)
        {
            Assert.IsNotNull(header.V4);
            Assert.AreEqual(0x4000u, header.V4.RawChunkSize);
            Assert.AreEqual(header.HashTableSize * 16L, header.V4.HashTableSize64);
            Assert.AreEqual(16, header.V4.Md5MpqHeader.Length);
        }
        else
        {
            Assert.IsNull(header.V4);
        }
    }

    [TestMethod]
    public void Find_ReadsSc2UserData()
    {
        var expected = ExpectedArchive.Load("sc2-userdata.SC2Replay");
        using var stream = File.OpenRead(TestDataPath.Get("sc2-userdata.SC2Replay"));

        var (_, userData, _) = MpqHeaderReader.Find(stream);

        Assert.IsNotNull(userData);
        Assert.AreEqual((uint)expected.UserData!.HeaderOffset, userData.HeaderOffset);
        Assert.AreEqual((uint)expected.UserData.UserDataSize, userData.UserDataSize);
        CollectionAssert.AreEqual(Convert.FromBase64String(expected.UserData.ContentBase64), userData.Content.ToArray());
        Assert.AreEqual((uint)userData.Content.Length, userData.UserDataHeaderSize);
    }

    [TestMethod]
    public void Find_SearchesAt512ByteSteps()
    {
        byte[] mpq = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        using var stream = new MemoryStream([.. new byte[0x400], .. mpq]);

        var (header, userData, headerOffset) = MpqHeaderReader.Find(stream);

        Assert.AreEqual(0x400, headerOffset);
        Assert.IsNull(userData);
        Assert.AreEqual(MpqFormatVersion.Version1, header.FormatVersion);
    }

    [TestMethod]
    public void Find_IgnoresHeaderOffAlignment()
    {
        byte[] mpq = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        using var stream = new MemoryStream([.. new byte[0x100], .. mpq]);

        Assert.ThrowsExactly<InvalidDataException>(() => MpqHeaderReader.Find(stream));
    }

    [TestMethod]
    public void Find_ThrowsWhenNoHeader()
    {
        using var stream = new MemoryStream(new byte[0x1000]);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqHeaderReader.Find(stream));
        using var empty = new MemoryStream();
        Assert.ThrowsExactly<InvalidDataException>(() => MpqHeaderReader.Find(empty));
    }

    private static uint SignatureAt(byte[] data, long position) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)position));
}
