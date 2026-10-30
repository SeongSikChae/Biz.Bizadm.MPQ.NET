using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class ListFileAttributesTests
{
    public static IEnumerable<object[]> AllArchives =>
    [
        ["v1-zlib.mpq"], ["v1-pkware.mpq"], ["v1-encrypted.mpq"], ["v1-sector-options.mpq"], ["v1-legacy-masks.mpq"],
        ["v1-weak-signed.mpq"], ["v2-bzip2.mpq"], ["v2-single-unit.mpq"], ["sc2-userdata.SC2Replay"], ["patch-base.mpq"],
        ["patch-1.mpq"], ["v3-lzma.mpq"], ["v4-mixed.mpq"],
    ];

    // patch-1.mpq is excluded where the expected file describes the patch chain instead of the archive.
    public static IEnumerable<object[]> SingleArchives => AllArchives.Where(a => (string)a[0] != "patch-1.mpq");

    [TestMethod]
    [DynamicData(nameof(SingleArchives))]
    public void Open_NamesEveryFileFromListFile(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        using var mpq = MpqArchive.Open(TestDataPath.Get(archive));
        var entries = mpq.Entries.ToList();

        Assert.IsTrue(entries.All(e => e.Name is not null), "unnamed: " + string.Join(", ", entries.Where(e => e.Name is null).Select(e => e.BlockIndex)));
        CollectionAssert.IsSubsetOf(expected.Files.Select(f => f.Name).ToList(), entries.Select(e => e.Name).ToList());
    }

    /// <summary>Parsing and re-serializing StormLib's (listfile) gives the same bytes.</summary>
    [TestMethod]
    [DynamicData(nameof(AllArchives))]
    public void ListFile_RoundTripsStormLibBytes(string archive)
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get(archive));
        byte[] original = ReadAll(mpq, ListFile.ListFileName);

        CollectionAssert.AreEqual(original, ListFile.Serialize(ListFile.Parse(original)));
    }

    /// <summary>CRC32 and MD5 in (attributes) match the file data (ADPCM files hold the hashes of the original PCM).</summary>
    [TestMethod]
    [DynamicData(nameof(SingleArchives))]
    public void Attributes_MatchFileData(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        var table = LoadTableWithAttributes(archive, out _, out _);

        foreach (var file in expected.Files.Where(f => !f.Internal && !f.Lossy))
        {
            using var mpq = MpqArchive.Open(TestDataPath.Get(archive));
            byte[] data = ReadAll(mpq, file.Name);
            var entry = table.Find(file.Name)!;
            Assert.AreEqual(Crc32.Compute(data), entry.Crc32, file.Name);
            // StormLib leaves the MD5 of an empty file as zeros.
            CollectionAssert.AreEqual(data.Length == 0 ? new byte[16] : MD5.HashData(data), entry.Md5, file.Name);
            Assert.AreNotEqual(0L, entry.FileTime, file.Name);
        }
    }

    /// <summary>Parsing and re-serializing StormLib's (attributes) gives the same bytes.</summary>
    [TestMethod]
    [DynamicData(nameof(AllArchives))]
    public void Attributes_RoundTripStormLibBytes(string archive)
    {
        var table = LoadTableWithAttributes(archive, out var flags, out byte[] original);

        // The patch bit flag is derived from the entries again, as in StormLib CreateAttributesFile.
        byte[] serialized = MpqAttributes.Serialize(flags & ~MpqAttributeFlags.PatchBit, table.Entries, BlockTableSize(archive));
        CollectionAssert.AreEqual(original, serialized);
    }

    [TestMethod]
    public void ExternalListFile_NamesFilesWhenListFileIsUnreadable()
    {
        byte[] data = CorruptListFile("v1-zlib.mpq");

        using (var mpq = MpqArchive.Open(new MemoryStream(data, writable: false)))
        {
            Assert.IsFalse(mpq.Entries.Any(e => e.Name == "readme.txt"), "the corrupt (listfile) must be ignored");
            Assert.IsTrue(mpq.Entries.Any(e => e.Name is null));
        }

        var names = new[] { "readme.txt", @"data\random.bin", @"data\zeros.bin", @"data\small.txt", @"data\empty.txt", "text/slash.txt" };
        using var named = MpqArchive.Open(new MemoryStream(data, writable: false), options: new MpqOpenOptions { ExternalListFile = names });
        CollectionAssert.IsSubsetOf(names, named.Entries.Select(e => e.Name).ToList());

        Assert.ThrowsExactly<InvalidDataException>(() =>
            MpqArchive.Open(new MemoryStream(data, writable: false), options: new MpqOpenOptions { Strict = true }));
    }

    [TestMethod]
    public void AddListFile_NamesOnlyExistingUnnamedFiles()
    {
        using var mpq = MpqArchive.Open(new MemoryStream(CorruptListFile("v1-zlib.mpq"), writable: false));
        Assert.AreEqual(0, mpq.Entries.Count(e => e.Name == "readme.txt"));

        mpq.AddListFile(["README.TXT", "missing.txt", ""]);

        Assert.AreEqual(1, mpq.Entries.Count(e => e.Name == "README.TXT"));
        Assert.IsFalse(mpq.Entries.Any(e => e.Name == "missing.txt"));
        mpq.AddListFile(["readme.txt"]);
        Assert.AreEqual(1, mpq.Entries.Count(e => e.Name == "README.TXT"), "an existing name is kept");
    }

    /// <summary>A (listfile) declaring a huge size is skipped before any allocation (StormLib MAX_LISTFILE_SIZE).</summary>
    [TestMethod]
    public void Open_SkipsOversizedListFile()
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        using var probe = new MemoryStream(data);
        var (header, _, _) = MpqHeaderReader.Find(probe);
        var table = MpqFileTable.Load(probe, header, 0);
        int blockIndex = table.Entries.ToList().IndexOf(table.Find(ListFile.ListFileName)!);

        // Rewrite the block table with FileSize = 0xFFFFFFF0 for (listfile).
        int pos = (int)header.BlockTablePosition, size = (int)header.BlockTableSize * 16;
        byte[] block = data.AsSpan(pos, size).ToArray();
        StormCrypto.DecryptBlock(block.AsSpan(), StormCrypto.BlockTableKey);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(blockIndex * 16 + 8), 0xFFFFFFF0);
        StormCrypto.EncryptBlock(block.AsSpan(), StormCrypto.BlockTableKey);
        block.CopyTo(data, pos);

        using (var mpq = MpqArchive.Open(new MemoryStream(data, writable: false)))
            Assert.IsFalse(mpq.Entries.Any(e => e.Name == "readme.txt"));
        Assert.ThrowsExactly<InvalidDataException>(() =>
            MpqArchive.Open(new MemoryStream(data, writable: false), options: new MpqOpenOptions { Strict = true }));
    }

    /// <summary>Without a HET table, StormLib names every hash slot with the name pair, even outside the probe chain.</summary>
    [TestMethod]
    public void AssignName_ScansWholeHashTable()
    {
        const string name = "far.txt";
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & 7;
        var hash = Enumerable.Repeat(new MpqHashEntry(0, 0, 0, 0, 0, MpqHashEntry.Free), 8).ToArray();
        hash[(start + 2) & 7] = new MpqHashEntry(a, b, 0, 0, 0, 0); // a Free slot precedes it in the probe chain
        var entry = new MpqFileEntry { Flags = MpqFileFlags.Exists };
        var table = new MpqFileTable(hash, [entry]);

        Assert.IsNull(table.Find(name));
        Assert.IsTrue(table.AssignName(name));
        Assert.AreEqual(name, entry.FileName);
    }

    [TestMethod]
    public void ListFile_ParsesLinesLikeStormLib()
    {
        byte[] data = Encoding.UTF8.GetBytes("a.txt\r\nb c.txt\n\n\rdir\\\td.txt\r한글.txt");
        CollectionAssert.AreEqual(new[] { "a.txt", "b c.txt", "dir\\\td.txt", "한글.txt" }, ListFile.Parse(data));
    }

    [TestMethod]
    public void ListFile_SerializeSortsDedupesAndSkipsInternalNames()
    {
        byte[] data = ListFile.Serialize(["b.txt", "A.txt", "a.TXT", "(listfile)", "(Attributes)", "File00000012.xxx", "Zeta", "_under"]);
        // _stricmp lowercases letters before comparing, so '_' (0x5F) sorts before 'a' (0x61).
        Assert.AreEqual("_under\r\nA.txt\r\nb.txt\r\nZeta\r\n", Encoding.UTF8.GetString(data));
    }

    private static MpqFileTable LoadTableWithAttributes(string archive, out MpqAttributeFlags flags, out byte[] attributes)
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get(archive));
        attributes = ReadAll(mpq, ListFile.AttributesName);
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, headerOffset);
        flags = MpqAttributes.Apply(attributes, (int)header.BlockTableSize, table.Entries);
        return table;
    }

    private static int BlockTableSize(string archive)
    {
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        return (int)MpqHeaderReader.Find(stream).Header.BlockTableSize;
    }

    /// <summary>Copy of the archive whose (listfile) data is overwritten, so reading it fails.</summary>
    private static byte[] CorruptListFile(string archive)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get(archive));
        using var stream = new MemoryStream(data);
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        var entry = MpqFileTable.Load(stream, header, headerOffset).Find(ListFile.ListFileName)!;
        data.AsSpan((int)(headerOffset + entry.FilePosition), (int)entry.CompressedSize).Fill(0xA5);
        return data;
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
