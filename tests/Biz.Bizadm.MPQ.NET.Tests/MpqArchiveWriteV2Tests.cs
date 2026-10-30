using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveWriteV2Tests
{
    private static readonly MpqArchiveCreateOptions V2 = new() { FormatVersion = MpqFormatVersion.Version2 };
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-write-v2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));
    private static readonly byte[] Random = CreateRandom(50000);

    public static IEnumerable<object[]> Cases =>
    [
        ["zlib", MpqCompressionType.Zlib, false, false, false],
        ["bzip2", MpqCompressionType.BZip2, false, false, false],
        ["lzma", MpqCompressionType.Lzma, false, false, false],
        ["single-unit", MpqCompressionType.Zlib, true, false, false],
        ["sector-crc", MpqCompressionType.Zlib, false, true, false],
        ["encrypted-fixkey", MpqCompressionType.Zlib, false, false, true],
        ["single-unit-encrypted", MpqCompressionType.Zlib, true, false, true],
    ];

    /// <summary>v2 archives round-trip with a 44-byte header and StormLib reads them with the same content.</summary>
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

        using (var mpq = MpqArchive.Create(path, V2))
        {
            foreach (var (fileName, data) in files)
                mpq.AddFile(fileName, new MemoryStream(data), options);
        }

        byte[] raw = File.ReadAllBytes(path);
        Assert.AreEqual(0x2Cu, BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4)));
        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqFormatVersion.Version2, mpq.Header.FormatVersion);
            Assert.AreEqual(0, mpq.Header.HiBlockTablePosition);
            Assert.AreEqual(raw.Length, mpq.Header.ArchiveSize);
            foreach (var (fileName, data) in files)
            {
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
                var flags = mpq.Entries.Single(e => e.Name == fileName).Flags;
                if (data.Length > 0)
                    Assert.AreEqual(singleUnit, flags.HasFlag(MpqFileFlags.SingleUnit), fileName);
            }
            CollectionAssert.AreEquivalent(files.Keys.ToList(), ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version2, 4096, files);
    }

    /// <summary>
    /// StormLib GetDefaultSpecialFileFlags: v2+ internal files are single-unit up to 0x4000 bytes and use sector CRCs
    /// above. The flags are chosen when the file is first saved and kept afterwards.
    /// </summary>
    [TestMethod]
    public void Flush_ChoosesInternalFileFlagsBySizeOnFirstSave()
    {
        string small = Path.Combine(_directory, "small.mpq");
        using (var mpq = MpqArchive.Create(small, V2))
        {
            mpq.AddFile("a.txt", new MemoryStream(Text));
            mpq.Flush();
            AddManyFiles(mpq, 0, 1000);
        }

        string large = Path.Combine(_directory, "large.mpq");
        using (var mpq = MpqArchive.Create(large, V2))
            AddManyFiles(mpq, 0, 1000);

        using (var mpq = MpqArchive.Open(small))
        {
            Assert.IsTrue(ReadAll(mpq, ListFile.ListFileName).Length > 0x4000);
            Assert.AreEqual(MpqFileFlags.Compress | MpqFileFlags.SingleUnit | MpqFileFlags.Exists, FlagsOf(mpq, ListFile.ListFileName));
            Assert.AreEqual(MpqFileFlags.Compress | MpqFileFlags.SingleUnit | MpqFileFlags.Exists, FlagsOf(mpq, ListFile.AttributesName));
        }
        using (var mpq = MpqArchive.Open(large))
        {
            Assert.AreEqual(MpqFileFlags.Compress | MpqFileFlags.SectorCrc | MpqFileFlags.Exists, FlagsOf(mpq, ListFile.ListFileName));
            Assert.AreEqual(MpqFileFlags.Compress | MpqFileFlags.SectorCrc | MpqFileFlags.Exists, FlagsOf(mpq, ListFile.AttributesName));
        }

        var files = Enumerable.Range(0, 1000).ToDictionary(FileName, i => Encoding.ASCII.GetBytes(FileName(i)));
        StormLibVerifier.AssertStormLibReads(large, MpqFormatVersion.Version2, 4096, files);
        files["a.txt"] = Text;
        StormLibVerifier.AssertStormLibReads(small, MpqFormatVersion.Version2, 4096, files);
    }

    [TestMethod]
    public void AddFile_ToOpenedV2ArchiveKeepsExistingFiles()
    {
        var expected = ExpectedArchive.Load("v2-bzip2.mpq");
        string path = Path.Combine(_directory, "opened.mpq");
        File.Copy(TestDataPath.Get("v2-bzip2.mpq"), path);
        uint blocksBefore;
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            Assert.AreEqual(MpqFormatVersion.Version2, mpq.Header.FormatVersion);
            blocksBefore = mpq.Header.BlockTableSize;
            mpq.AddFile(@"data\new.bin", new MemoryStream(Random), new MpqAddFileOptions { Compression = MpqCompressionType.BZip2 });
        }

        var files = new Dictionary<string, byte[]> { [@"data\new.bin"] = Random };
        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqFormatVersion.Version2, mpq.Header.FormatVersion);
            Assert.AreEqual(0x2Cu, mpq.Header.HeaderSize);
            Assert.AreEqual(blocksBefore + 1, mpq.Header.BlockTableSize);
            foreach (var file in expected.Files.Where(f => !f.Internal))
                files[file.Name] = ReadAll(mpq, file.Name);
            CollectionAssert.Contains(ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)), @"data\new.bin");
        }
        foreach (var file in expected.Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version2, 4096, files);
    }

    /// <summary>
    /// A file is moved to end above 4 GB; files added after it start above 4 GB, so Flush writes a hi-block table
    /// and the high words of the table positions. Uses <see cref="SparseFileStream"/>, so no disk space is used.
    /// </summary>
    [TestMethod]
    public void Flush_WritesHiBlockTableAbove4GB()
    {
        const long farPosition = 0xFFFF_FF00;
        using var stream = new SparseFileStream();
        using (var mpq = MpqArchive.Create(stream, V2, leaveOpen: true))
        {
            mpq.AddFile("low.txt", new MemoryStream(Text));
            mpq.AddFile("far.bin", new MemoryStream(Random), new MpqAddFileOptions { Compression = MpqCompressionType.None });
        }
        MoveFile(stream, "far.bin", farPosition);

        var encrypted = new MpqAddFileOptions { Encrypt = true, FixKey = true, SectorCrc = true };
        using (var mpq = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true))
        {
            CollectionAssert.AreEqual(Random, ReadAll(mpq, "far.bin"));
            mpq.AddFile("high.txt", new MemoryStream(Text), encrypted);
        }

        long fourGB = 0x1_0000_0000;
        using (var mpq = MpqArchive.Open(stream, leaveOpen: true))
        {
            Assert.IsTrue(mpq.Header.HiBlockTablePosition > fourGB);
            Assert.IsTrue(mpq.Header.HashTablePosition > fourGB);
            Assert.IsTrue(mpq.Header.BlockTablePosition > fourGB);
            Assert.AreEqual(stream.Length, mpq.Header.HiBlockTablePosition + mpq.Header.BlockTableSize * 2);
            CollectionAssert.AreEqual(Text, ReadAll(mpq, "low.txt"));
            CollectionAssert.AreEqual(Random, ReadAll(mpq, "far.bin"));
            CollectionAssert.AreEqual(Text, ReadAll(mpq, "high.txt"));
            CollectionAssert.AreEquivalent(new[] { "low.txt", "far.bin", "high.txt" }, ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        // The hi-block table holds the high word of every file position.
        var (_, blocks) = ReadBlockTable(stream);
        byte[] hiBlock = new byte[blocks.Length / 16 * 2];
        stream.Position = (long)BinaryPrimitives.ReadUInt64LittleEndian(ReadHeader(stream).AsSpan(0x20));
        stream.ReadExactly(hiBlock);
        using (var mpq = MpqArchive.Open(stream, leaveOpen: true))
        {
            ushort HiWord(string name) => BinaryPrimitives.ReadUInt16LittleEndian(hiBlock.AsSpan(mpq.Entries.Single(e => e.Name == name).BlockIndex * 2));
            Assert.AreEqual(0, HiWord("low.txt"));
            Assert.AreEqual(0, HiWord("far.bin"));
            Assert.AreEqual(1, HiWord("high.txt"));
            Assert.AreEqual(1, HiWord(ListFile.ListFileName));
        }
    }

    /// <summary>
    /// StormLib reads a v2 header whose size is not 0x2C as a malformed v1 header; writing such an archive must
    /// keep the 32-byte header and not overwrite the data after it.
    /// </summary>
    [TestMethod]
    public void MalformedV2Header_IsReadAndWrittenAsV1()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text), new MpqAddFileOptions { Compression = MpqCompressionType.None });
        BinaryPrimitives.WriteUInt16LittleEndian(stream.GetBuffer().AsSpan(0x0C), (ushort)MpqFormatVersion.Version2);

        using (var mpq = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true))
        {
            Assert.AreEqual(MpqFormatVersion.Version1, mpq.Header.FormatVersion);
            Assert.AreEqual(0x20u, mpq.Header.HeaderSize);
            mpq.AddFile("b.txt", new MemoryStream(Random));
        }

        using (var mpq = MpqArchive.Open(stream, leaveOpen: true))
        {
            Assert.AreEqual(MpqFormatVersion.Version1, mpq.Header.FormatVersion);
            CollectionAssert.AreEqual(Text, ReadAll(mpq, "a.txt"));
            CollectionAssert.AreEqual(Random, ReadAll(mpq, "b.txt"));
        }
    }

    [TestMethod]
    public void Flush_OmitsHiBlockTableBelow4GB()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, V2, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text));

        byte[] header = ReadHeader(stream);
        Assert.AreEqual(0ul, BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x20)));
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x28)));
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x2A)));
    }

    private static string FileName(int i) => $@"files\file{i:D4}.txt";

    private static void AddManyFiles(MpqArchive mpq, int start, int count)
    {
        for (int i = start; i < start + count; i++)
            mpq.AddFile(FileName(i), new MemoryStream(Encoding.ASCII.GetBytes(FileName(i))));
    }

    private static MpqFileFlags FlagsOf(MpqArchive mpq, string name) => mpq.Entries.Single(e => e.Name == name).Flags;

    private static byte[] ReadHeader(Stream stream)
    {
        var header = new byte[0x2C];
        stream.Position = 0;
        stream.ReadExactly(header);
        return header;
    }

    private static (long Position, byte[] Data) ReadBlockTable(Stream stream)
    {
        byte[] header = ReadHeader(stream);
        long position = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x14))
            | (long)BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x2A)) << 32;
        var data = new byte[BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x1C)) * 16];
        stream.Position = position;
        stream.ReadExactly(data);
        StormCrypto.DecryptBlock(data.AsSpan(), StormCrypto.BlockTableKey);
        return (position, data);
    }

    /// <summary>Copies the stored data of an unencrypted file to <paramref name="newPosition"/> and updates its block entry.</summary>
    private static void MoveFile(Stream stream, string name, long newPosition)
    {
        int blockIndex;
        using (var mpq = MpqArchive.Open(stream, leaveOpen: true))
            blockIndex = mpq.Entries.Single(e => e.Name == name).BlockIndex;

        var (tablePosition, blocks) = ReadBlockTable(stream);
        var entry = blocks.AsSpan(blockIndex * 16, 16);
        var stored = new byte[BinaryPrimitives.ReadUInt32LittleEndian(entry[4..])];
        stream.Position = BinaryPrimitives.ReadUInt32LittleEndian(entry);
        stream.ReadExactly(stored);
        stream.Position = newPosition;
        stream.Write(stored);

        BinaryPrimitives.WriteUInt32LittleEndian(entry, (uint)newPosition);
        StormCrypto.EncryptBlock(blocks.AsSpan(), StormCrypto.BlockTableKey);
        stream.Position = tablePosition;
        stream.Write(blocks);
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
