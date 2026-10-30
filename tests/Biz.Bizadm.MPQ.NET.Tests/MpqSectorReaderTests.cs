using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqSectorReaderTests
{
    /// <summary>Every fixture archive (patch-1.mpq is excluded: its expected file describes the patch chain).</summary>
    public static IEnumerable<object[]> AllArchives =>
    [
        ["v1-zlib.mpq"], ["v1-encrypted.mpq"], ["v1-sector-options.mpq"], ["v1-weak-signed.mpq"],
        ["sc2-userdata.SC2Replay"], ["patch-base.mpq"], ["v2-single-unit.mpq"], ["v1-pkware.mpq"], ["v1-legacy-masks.mpq"],
        ["v2-bzip2.mpq"], ["v3-lzma.mpq"], ["v4-mixed.mpq"],
    ];

    [TestMethod]
    [DynamicData(nameof(AllArchives))]
    public void ReadAll_MatchesStormLib(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);

        foreach (var file in expected.Files)
        {
            byte[] data = CreateReader(stream, header, headerOffset, table, file.Name).ReadAll();
            Assert.AreEqual(file.Size, data.Length, file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(data)), file.Name);
        }
    }

    /// <summary>
    /// Covers sector CRC, uncompressed and single-unit files, plus encrypted files with and without KEY_V2.
    /// Single-unit files are in a v2 archive because StormLib strips the flag in v1 archives.
    /// </summary>
    [TestMethod]
    [DataRow("v1-sector-options.mpq", @"data\zeros.bin", (uint)(MpqFileFlags.SectorCrc | MpqFileFlags.Compress))]
    [DataRow("v1-sector-options.mpq", @"data\random.bin", 0u)]
    [DataRow("v1-encrypted.mpq", "readme.txt", (uint)(MpqFileFlags.Encrypted | MpqFileFlags.Compress))]
    [DataRow("v1-encrypted.mpq", @"data\random.bin", (uint)(MpqFileFlags.Encrypted | MpqFileFlags.FixKey | MpqFileFlags.Compress))]
    [DataRow("v1-encrypted.mpq", @"data\small.txt", (uint)(MpqFileFlags.Encrypted | MpqFileFlags.FixKey))]
    [DataRow("v2-single-unit.mpq", "readme.txt", (uint)(MpqFileFlags.SingleUnit | MpqFileFlags.Compress))]
    [DataRow("v2-single-unit.mpq", @"data\zeros.bin", (uint)(MpqFileFlags.SingleUnit | MpqFileFlags.Encrypted | MpqFileFlags.FixKey | MpqFileFlags.Compress))]
    [DataRow("v2-single-unit.mpq", @"data\random.bin", (uint)MpqFileFlags.SingleUnit)]
    [DataRow("v2-single-unit.mpq", @"data\small.txt", (uint)(MpqFileFlags.SingleUnit | MpqFileFlags.Encrypted))]
    public void ReadAll_HandlesStorageOptions(string archive, string name, uint flags)
    {
        var expected = ExpectedArchive.Load(archive).Files.Single(f => f.Name == name);
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);

        var entry = table.Find(name)!;
        var mask = MpqFileFlags.SingleUnit | MpqFileFlags.SectorCrc | MpqFileFlags.Encrypted | MpqFileFlags.FixKey | MpqFileFlags.Compress | MpqFileFlags.Implode;
        Assert.AreEqual((MpqFileFlags)flags, entry.Flags & mask, "fixture flags");

        byte[] data = CreateReader(stream, header, headerOffset, table, name).ReadAll();
        Assert.AreEqual(expected.Sha256, Convert.ToHexString(SHA256.HashData(data)));
    }

    [TestMethod]
    public void ReadSector_ReadsOneSectorAtRandom()
    {
        using var stream = File.OpenRead(TestDataPath.Get("v1-zlib.mpq"));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);
        var reader = CreateReader(stream, header, headerOffset, table, "readme.txt");
        byte[] all = reader.ReadAll();
        Assert.IsTrue(reader.SectorCount > 2);

        var sector = new byte[reader.SectorSize];
        int last = reader.SectorCount - 1;
        int length = reader.ReadSector(last, sector);

        Assert.AreEqual(all.Length - last * reader.SectorSize, length);
        CollectionAssert.AreEqual(all[(last * reader.SectorSize)..], sector[..length]);
    }

    [TestMethod]
    public void ReadAll_ReturnsEmptyForEmptyFile()
    {
        using var stream = File.OpenRead(TestDataPath.Get("v1-zlib.mpq"));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);
        var reader = CreateReader(stream, header, headerOffset, table, @"data\empty.txt");

        Assert.AreEqual(0, reader.SectorCount);
        Assert.AreEqual(0, reader.ReadAll().Length);
    }

    [TestMethod]
    public void ReadAll_FailsWithWrongKey()
    {
        using var stream = File.OpenRead(TestDataPath.Get("v1-encrypted.mpq"));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);
        var entry = table.Find("readme.txt")!;
        var reader = new MpqSectorReader(stream, headerOffset, entry, header.FormatVersion, header.SectorSize, fileKey: 0x12345678);

        Assert.Throws<Exception>(() => reader.ReadAll());
    }

    private static MpqSectorReader CreateReader(Stream stream, MpqHeader header, long headerOffset, MpqFileTable table, string name)
    {
        var entry = table.Find(name) ?? throw new AssertFailedException($"{name} not found.");
        uint key = entry.Flags.HasFlag(MpqFileFlags.Encrypted)
            ? StormCrypto.GetFileKey(name, entry.FilePosition, entry.FileSize, entry.Flags.HasFlag(MpqFileFlags.FixKey))
            : 0;
        return new MpqSectorReader(stream, headerOffset, entry, header.FormatVersion, header.SectorSize, key);
    }
}
