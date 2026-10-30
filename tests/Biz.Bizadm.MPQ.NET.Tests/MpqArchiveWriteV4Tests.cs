using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveWriteV4Tests
{
    private static readonly MpqArchiveCreateOptions V4 = new() { FormatVersion = MpqFormatVersion.Version4 };
    private static readonly MpqOpenOptions Strict = new() { Strict = true };
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-write-v4-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));
    private static readonly byte[] Random = CreateRandom(50000);

    public static IEnumerable<object[]> Cases =>
    [
        ["zlib", MpqCompressionType.Zlib, false, false, false],
        ["lzma", MpqCompressionType.Lzma, false, false, false],
        ["sector-crc", MpqCompressionType.Zlib, false, true, false],
        ["single-unit", MpqCompressionType.Zlib, true, false, false],
        ["encrypted", MpqCompressionType.BZip2, false, false, true],
        ["none", MpqCompressionType.None, false, false, false],
    ];

    /// <summary>
    /// v4 archives get a 0xD0-byte header with table sizes and MD5s; strict opening verifies every MD5 and
    /// StormLib reads the same content.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(Cases))]
    public void Create_AddFile_RoundTripsAndStormLibReads(string name, MpqCompressionType compression, bool singleUnit, bool sectorCrc, bool encrypt)
    {
        var options = new MpqAddFileOptions { Compression = compression, SingleUnit = singleUnit, SectorCrc = sectorCrc, Encrypt = encrypt, FixKey = encrypt };
        var files = new Dictionary<string, byte[]>
        {
            ["readme.txt"] = Text,
            [@"data\random.bin"] = Random,
            [@"data\small.txt"] = "abc"u8.ToArray(),
            [@"data\empty.txt"] = [],
            ["text/slash.txt"] = "slash"u8.ToArray(),
        };
        string path = Path.Combine(_directory, name + ".mpq");

        using (var mpq = MpqArchive.Create(path, V4))
        {
            foreach (var (fileName, data) in files)
                mpq.AddFile(fileName, new MemoryStream(data), options);
        }

        using (var mpq = MpqArchive.Open(path, options: Strict))
        {
            Assert.AreEqual(MpqFormatVersion.Version4, mpq.Header.FormatVersion);
            Assert.AreEqual(0xD0u, mpq.Header.HeaderSize);
            Assert.AreEqual(0x4000u, mpq.Header.V4!.RawChunkSize);
            Assert.AreEqual(new FileInfo(path).Length, mpq.Header.ArchiveSize);
            foreach (var (fileName, data) in files)
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
            CollectionAssert.AreEquivalent(files.Keys.ToList(), ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        AssertRawChunkMd5s(path);
        MpqArchiveWriteV3Tests.AssertHetFindsEveryFile(path, files.Keys);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version4, 4096, files);
    }

    /// <summary>StormLib WriteSectorChecksums: with raw chunk MD5s the sector CRC table is left empty.</summary>
    [TestMethod]
    public void SectorCrc_TableIsEmpty()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, V4, leaveOpen: true))
            mpq.AddFile("a.bin", new MemoryStream(Random), new MpqAddFileOptions { SectorCrc = true });

        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        var entry = table.Find("a.bin")!;
        Assert.IsTrue(entry.Flags.HasFlag(MpqFileFlags.SectorCrc));
        int sectors = (Random.Length - 1) / header.SectorSize + 1;
        var offsets = new byte[(sectors + 2) * 4];
        stream.Position = offset + entry.FilePosition;
        stream.ReadExactly(offsets);
        Assert.AreEqual(BitConverter.ToUInt32(offsets, sectors * 4), BitConverter.ToUInt32(offsets, (sectors + 1) * 4));
        Assert.AreEqual(entry.CompressedSize, BitConverter.ToUInt32(offsets, sectors * 4));
    }

    [TestMethod]
    public void Create_EmptyArchiveIsValid()
    {
        string path = Path.Combine(_directory, "empty.mpq");
        using (MpqArchive.Create(path, V4))
        {
        }

        using (var mpq = MpqArchive.Open(path, options: Strict))
            Assert.AreEqual(MpqFormatVersion.Version4, mpq.Header.FormatVersion);
        AssertRawChunkMd5s(path);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version4, 4096, new Dictionary<string, byte[]>());
    }

    [TestMethod]
    public void AddFile_ToOpenedV4ArchiveKeepsExistingFiles()
    {
        var expected = ExpectedArchive.Load("v4-mixed.mpq");
        string path = Path.Combine(_directory, "opened.mpq");
        File.Copy(TestDataPath.Get("v4-mixed.mpq"), path);
        uint rawChunkSize;
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            rawChunkSize = mpq.Header.V4!.RawChunkSize;
            mpq.AddFile(@"data\new.bin", new MemoryStream(Random));
        }

        var files = new Dictionary<string, byte[]> { [@"data\new.bin"] = Random };
        using (var mpq = MpqArchive.Open(path, options: Strict))
        {
            Assert.AreEqual(MpqFormatVersion.Version4, mpq.Header.FormatVersion);
            Assert.AreEqual(rawChunkSize, mpq.Header.V4!.RawChunkSize);
            foreach (var file in expected.Files.Where(f => !f.Internal))
                files[file.Name] = ReadAll(mpq, file.Name);
            CollectionAssert.AreEqual(Random, ReadAll(mpq, @"data\new.bin"));
        }
        foreach (var file in expected.Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);

        AssertRawChunkMd5s(path);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version4, expected.SectorSize, files);
    }

    /// <summary>
    /// The MD5 of every raw chunk follows each file's data and the HET/BET tables (StormLib WriteMpqDataMD5 /
    /// WriteMemDataMD5); the archive ends right after the tables.
    /// </summary>
    private static void AssertRawChunkMd5s(string path)
    {
        byte[] archive = File.ReadAllBytes(path);
        using var stream = new MemoryStream(archive);
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        long chunk = header.V4!.RawChunkSize;

        var blocks = table.Entries.Where(e => e.Flags.HasFlag(MpqFileFlags.Exists) && e.CompressedSize != 0)
            .Select(e => (e.FilePosition, Size: (long)e.CompressedSize))
            .Append((header.HetTablePosition, header.V4.HetTableSize64))
            .Append((header.BetTablePosition, header.V4.BetTableSize64));
        foreach (var (position, size) in blocks)
        {
            long md5Position = offset + position + size;
            for (long done = 0, i = 0; done < size; done += chunk, i++)
            {
                var data = archive.AsSpan((int)(offset + position + done), (int)Math.Min(chunk, size - done));
                var md5 = archive.AsSpan((int)(md5Position + i * 16), 16);
                CollectionAssert.AreEqual(MD5.HashData(data), md5.ToArray(), $"chunk {i} at {position:X}");
            }
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
