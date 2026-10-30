using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveWriteV3Tests
{
    private static readonly MpqArchiveCreateOptions V3 = new() { FormatVersion = MpqFormatVersion.Version3 };
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-write-v3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));
    private static readonly byte[] Random = CreateRandom(50000);

    public static IEnumerable<object[]> Cases =>
    [
        ["zlib", MpqCompressionType.Zlib, false, false],
        ["lzma", MpqCompressionType.Lzma, false, false],
        ["single-unit", MpqCompressionType.Zlib, true, false],
        ["encrypted", MpqCompressionType.BZip2, false, true],
    ];

    /// <summary>v3 archives get HET/BET tables next to the hash and block tables; both lookups find every file.</summary>
    [TestMethod]
    [DynamicData(nameof(Cases))]
    public void Create_AddFile_RoundTripsAndStormLibReads(string name, MpqCompressionType compression, bool singleUnit, bool encrypt)
    {
        var options = new MpqAddFileOptions { Compression = compression, SingleUnit = singleUnit, Encrypt = encrypt, FixKey = encrypt };
        var files = new Dictionary<string, byte[]>
        {
            ["readme.txt"] = Text,
            [@"data\random.bin"] = Random,
            [@"data\small.txt"] = "abc"u8.ToArray(),
            [@"data\empty.txt"] = [],
            ["text/slash.txt"] = "slash"u8.ToArray(),
        };
        string path = Path.Combine(_directory, name + ".mpq");

        using (var mpq = MpqArchive.Create(path, V3))
        {
            foreach (var (fileName, data) in files)
                mpq.AddFile(fileName, new MemoryStream(data), options);
        }

        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqFormatVersion.Version3, mpq.Header.FormatVersion);
            Assert.AreEqual(0x44u, mpq.Header.HeaderSize);
            Assert.AreEqual(new FileInfo(path).Length, mpq.Header.ArchiveSize);
            Assert.AreNotEqual(0, mpq.Header.HetTablePosition);
            Assert.AreNotEqual(0, mpq.Header.BetTablePosition);
            foreach (var (fileName, data) in files)
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
            CollectionAssert.AreEquivalent(files.Keys.ToList(), ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        AssertHetFindsEveryFile(path, files.Keys.Append(ListFile.ListFileName).Append(ListFile.AttributesName));
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version3, 4096, files);
    }

    /// <summary>
    /// StormLib rebuilds the HET table from the file table before saving, so rebuilding the tables of a StormLib
    /// archive must give the same bytes it wrote.
    /// </summary>
    [TestMethod]
    [DataRow("v3-lzma.mpq")]
    [DataRow("v4-mixed.mpq")]
    public void HetAndBet_MatchStormLibBytes(string archive)
    {
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var layout = MpqTableLayout.From(header, stream.Length, offset);
        var table = MpqFileTable.Load(stream, header, offset);
        byte[] het = MpqTableReader.LoadExtTable(stream, offset + header.HetTablePosition, layout.HetTableSize,
            MpqTableReader.HetSignature, StormCrypto.HashTableKey, default, false, "HET table");
        byte[] bet = MpqTableReader.LoadExtTable(stream, offset + header.BetTablePosition, layout.BetTableSize,
            MpqTableReader.BetSignature, StormCrypto.BlockTableKey, default, false, "BET table");

        var rebuilt = HetTable.Build(table.Entries);
        CollectionAssert.AreEqual(het, rebuilt.Serialize());
        CollectionAssert.AreEqual(bet, BetTable.Serialize(table.Entries, rebuilt));
    }

    [TestMethod]
    public void Create_EmptyArchiveIsValid()
    {
        string path = Path.Combine(_directory, "empty.mpq");
        using (MpqArchive.Create(path, V3))
        {
        }

        using (var mpq = MpqArchive.Open(path))
            Assert.AreEqual(MpqFormatVersion.Version3, mpq.Header.FormatVersion);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version3, 4096, new Dictionary<string, byte[]>());
    }

    /// <summary>StormLib SFileCreateArchive adds patch bits to (attributes) of v3+ archives.</summary>
    [TestMethod]
    public void Create_AttributesHavePatchBits()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, V3, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text));

        using (var reopened = MpqArchive.Open(stream, leaveOpen: true))
        {
            byte[] attributes = ReadAll(reopened, ListFile.AttributesName);
            Assert.AreEqual(100u, BinaryPrimitives.ReadUInt32LittleEndian(attributes));
            Assert.AreEqual(0x0Fu, BinaryPrimitives.ReadUInt32LittleEndian(attributes.AsSpan(4)));
        }

        // StormLib SAttrFileLoad keeps the flags, so the patch bits stay after the archive is modified.
        using (var modified = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true))
            modified.AddFile("b.txt", new MemoryStream(Random));
        using (var reopened = MpqArchive.Open(stream, leaveOpen: true))
            Assert.AreEqual(0x0Fu, BinaryPrimitives.ReadUInt32LittleEndian(ReadAll(reopened, ListFile.AttributesName).AsSpan(4)));
    }

    [TestMethod]
    public void AddFile_ToOpenedV3ArchiveKeepsExistingFiles()
    {
        var expected = ExpectedArchive.Load("v3-lzma.mpq");
        string path = Path.Combine(_directory, "opened.mpq");
        File.Copy(TestDataPath.Get("v3-lzma.mpq"), path);
        uint attributeFlags;
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            attributeFlags = BinaryPrimitives.ReadUInt32LittleEndian(ReadAll(mpq, ListFile.AttributesName).AsSpan(4));
            Assert.AreEqual(MpqFormatVersion.Version3, mpq.Header.FormatVersion);
            mpq.AddFile(@"data\new.bin", new MemoryStream(Random), new MpqAddFileOptions { Compression = MpqCompressionType.Lzma });
            // The HET table is rebuilt after each added file, so it finds the new file before Flush.
            Assert.IsTrue(mpq.Contains(@"data\new.bin"));
        }

        var files = new Dictionary<string, byte[]> { [@"data\new.bin"] = Random };
        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqFormatVersion.Version3, mpq.Header.FormatVersion);
            // StormLib keeps the (attributes) flags of an opened archive.
            Assert.AreEqual(attributeFlags, BinaryPrimitives.ReadUInt32LittleEndian(ReadAll(mpq, ListFile.AttributesName).AsSpan(4)));
            foreach (var file in expected.Files.Where(f => !f.Internal))
                files[file.Name] = ReadAll(mpq, file.Name);
            CollectionAssert.AreEqual(Random, ReadAll(mpq, @"data\new.bin"));
        }
        foreach (var file in expected.Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);

        AssertHetFindsEveryFile(path, files.Keys);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version3, expected.SectorSize, files);
    }

    [TestMethod]
    public void Create_RejectsV4()
    {
        Assert.ThrowsExactly<NotSupportedException>(() =>
            MpqArchive.Create(new MemoryStream(), new MpqArchiveCreateOptions { FormatVersion = MpqFormatVersion.Version4 }));
    }

    /// <summary>Looks every name up through the HET table only and compares with the hash table result.</summary>
    private static void AssertHetFindsEveryFile(string path, IEnumerable<string> names)
    {
        using var stream = File.OpenRead(path);
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        var het = table.Het;
        Assert.IsNotNull(het);
        foreach (string name in names)
        {
            int? index = het.FindIndex(het.HashName(name), table.Entries);
            Assert.IsNotNull(index, name);
            Assert.AreSame(table.Find(name), table.Entries[index.Value], name);
        }
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static byte[] CreateRandom(int length)
    {
        var data = new byte[length];
        new Random(7).NextBytes(data);
        return data;
    }
}
