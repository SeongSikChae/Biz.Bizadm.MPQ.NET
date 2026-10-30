using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveWriteV1Tests
{
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-write-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));
    private static readonly byte[] Random = CreateRandom(50000);
    private static readonly byte[] Sparse = CreateSparse(20000);

    public static IEnumerable<object[]> Cases =>
    [
        ["zlib", MpqCompressionType.Zlib, false, false, false],
        ["none", MpqCompressionType.None, false, false, false],
        ["pkware", MpqCompressionType.Pkware, false, false, false],
        ["bzip2", MpqCompressionType.BZip2, false, false, false],
        ["huffman", MpqCompressionType.Huffman, false, false, false],
        ["sparse-zlib", MpqCompressionType.Sparse | MpqCompressionType.Zlib, false, false, false],
        ["pkware-zlib", MpqCompressionType.Pkware | MpqCompressionType.Zlib, false, false, false],
        ["encrypted", MpqCompressionType.Zlib, true, false, false],
        ["encrypted-fixkey", MpqCompressionType.Zlib, true, true, false],
        ["encrypted-raw", MpqCompressionType.None, true, true, false],
        ["sector-crc", MpqCompressionType.Zlib, false, false, true],
    ];

    /// <summary>Every option combination round-trips and StormLib reads the archive with the same content.</summary>
    [TestMethod]
    [DynamicData(nameof(Cases))]
    public void Create_AddFile_RoundTripsAndStormLibReads(string name, MpqCompressionType compression, bool encrypt, bool fixKey, bool sectorCrc)
    {
        var options = new MpqAddFileOptions { Compression = compression, Encrypt = encrypt, FixKey = fixKey, SectorCrc = sectorCrc };
        var files = new Dictionary<string, byte[]>
        {
            ["readme.txt"] = Text,
            [@"data\random.bin"] = Random,
            [@"data\sparse.bin"] = Sparse,
            [@"data\small.txt"] = "abc"u8.ToArray(),
            [@"data\empty.txt"] = [],
            ["text/slash.txt"] = "slash"u8.ToArray(),
        };
        string path = Path.Combine(_directory, name + ".mpq");

        using (var mpq = MpqArchive.Create(path))
        {
            foreach (var (fileName, data) in files)
                mpq.AddFile(fileName, new MemoryStream(data), options);
        }

        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqFormatVersion.Version1, mpq.Header.FormatVersion);
            foreach (var (fileName, data) in files)
            {
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
                var entry = mpq.Entries.Single(e => e.Name == fileName);
                Assert.AreEqual(encrypt, entry.Flags.HasFlag(MpqFileFlags.Encrypted), fileName);
                Assert.AreEqual(sectorCrc && compression != MpqCompressionType.None && data.Length > 0,
                    entry.Flags.HasFlag(MpqFileFlags.SectorCrc) && data.Length > 0, fileName);
            }
            CollectionAssert.AreEquivalent(files.Keys.ToList(), ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096, files);
    }

    /// <summary>ADPCM is lossy; StormLib must decode exactly what this library decodes.</summary>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    public void AddFile_AdpcmWaveIsReadIdenticallyByStormLib(int channels)
    {
        byte[] wave = CreateSine(channels);
        var compression = (channels == 1 ? MpqCompressionType.AdpcmMono : MpqCompressionType.AdpcmStereo) | MpqCompressionType.Huffman;
        string path = Path.Combine(_directory, $"adpcm{channels}.mpq");

        using (var mpq = MpqArchive.Create(path))
            mpq.AddFile("tone.wav", new MemoryStream(wave), new MpqAddFileOptions { Compression = compression });

        byte[] decoded;
        using (var mpq = MpqArchive.Open(path))
            decoded = ReadAll(mpq, "tone.wav");

        Assert.AreEqual(wave.Length, decoded.Length);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096, new Dictionary<string, byte[]> { ["tone.wav"] = decoded });
    }

    [TestMethod]
    public void Flush_WritesAttributesMatchingFiles()
    {
        string path = Path.Combine(_directory, "attributes.mpq");
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("readme.txt", new MemoryStream(Text));
            mpq.AddFile(@"data\random.bin", new MemoryStream(Random));
        }

        using var stream = File.OpenRead(path);
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        using var mpq2 = MpqArchive.Open(path);
        byte[] attributes = ReadAll(mpq2, ListFile.AttributesName);
        MpqAttributes.Apply(attributes, (int)header.BlockTableSize, table.Entries);

        foreach (var (name, data) in new[] { ("readme.txt", Text), (@"data\random.bin", Random) })
        {
            var entry = table.Find(name)!;
            Assert.AreEqual(Crc32.Compute(data), entry.Crc32, name);
            CollectionAssert.AreEqual(MD5.HashData(data), entry.Md5, name);
        }
        Assert.AreEqual((int)header.BlockTableSize * 28 + 8, attributes.Length,"one CRC32 + FILETIME + MD5 per block, including (attributes)");
    }

    [TestMethod]
    public void Create_EmptyArchiveIsValid()
    {
        string path = Path.Combine(_directory, "empty.mpq");
        MpqArchive.Create(path).Dispose();

        using (var mpq = MpqArchive.Open(path))
            Assert.AreEqual(0, mpq.Entries.Count(e => !ListFile.IsInternalName(e.Name ?? "")));
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096, new Dictionary<string, byte[]>());
    }

    [TestMethod]
    public void AddFile_OverwriteReplacesContent()
    {
        string path = Path.Combine(_directory, "overwrite.mpq");
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("a.txt", new MemoryStream("first"u8.ToArray()));
            Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("a.txt", new MemoryStream("second"u8.ToArray())));
            mpq.AddFile("a.txt", new MemoryStream("second"u8.ToArray()), new MpqAddFileOptions { Overwrite = true });
        }

        using (var mpq = MpqArchive.Open(path))
        {
            CollectionAssert.AreEqual("second"u8.ToArray(), ReadAll(mpq, "a.txt"));
            Assert.AreEqual(1, mpq.Entries.Count(e => e.Name == "a.txt"));
        }
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096,
            new Dictionary<string, byte[]> { ["a.txt"] = "second"u8.ToArray() });
    }

    [TestMethod]
    public void AddFile_FailsWhenHashTableIsFull()
    {
        using var mpq = MpqArchive.Create(new MemoryStream(), new MpqArchiveCreateOptions
        {
            HashTableSize = 4, CreateListFile = false, CreateAttributes = false,
        });
        for (int i = 0; i < 4; i++)
            mpq.AddFile($"f{i}.txt", new MemoryStream([1, 2, 3]));

        Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("f4.txt", new MemoryStream([1])));
    }

    /// <summary>(listfile) and (attributes) keep reserved entries, so Flush never runs out of hash slots.</summary>
    [TestMethod]
    public void AddFile_KeepsEntriesReservedForInternalFiles()
    {
        string path = Path.Combine(_directory, "reserved.mpq");
        using (var mpq = MpqArchive.Create(path, new MpqArchiveCreateOptions { HashTableSize = 4 }))
        {
            mpq.AddFile("a.txt", new MemoryStream([1]));
            mpq.AddFile("b.txt", new MemoryStream([2]));
            Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("c.txt", new MemoryStream([3])));
        }

        using (var mpq = MpqArchive.Open(path))
            Assert.AreEqual(4, mpq.Entries.Count());
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096,
            new Dictionary<string, byte[]> { ["a.txt"] = [1], ["b.txt"] = [2] });
    }

    /// <summary>Flush defragments the file table (StormLib DefragmentFileTable), so repeated flushes add no dead blocks.</summary>
    [TestMethod]
    public void Flush_DefragmentsFileTable()
    {
        string path = Path.Combine(_directory, "defrag.mpq");
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("a.txt", new MemoryStream(Text));
            mpq.Flush();
            mpq.AddFile("b.txt", new MemoryStream(Random));
            mpq.Flush();
            mpq.AddFile("c.txt", new MemoryStream(Sparse));
        }

        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(5u, mpq.Header.BlockTableSize, "3 files + (listfile) + (attributes)");
            Assert.AreEqual(5, mpq.Entries.Count());
        }
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096,
            new Dictionary<string, byte[]> { ["a.txt"] = Text, ["b.txt"] = Random, ["c.txt"] = Sparse });
    }

    /// <summary>Adding to an opened StormLib v1 archive rewrites the internal files; StormLib reads old and new files.</summary>
    [TestMethod]
    public void AddFile_ToOpenedArchiveKeepsExistingFiles()
    {
        var expected = ExpectedArchive.Load("v1-zlib.mpq");
        string path = Path.Combine(_directory, "opened.mpq");
        File.Copy(TestDataPath.Get("v1-zlib.mpq"), path);
        uint blocksBefore;
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            blocksBefore = mpq.Header.BlockTableSize;
            mpq.AddFile(@"data\new.bin", new MemoryStream(Random));
        }

        var files = new Dictionary<string, byte[]> { [@"data\new.bin"] = Random };
        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(blocksBefore + 1, mpq.Header.BlockTableSize);
            foreach (var file in expected.Files.Where(f => !f.Internal))
                files[file.Name] = ReadAll(mpq, file.Name);
            CollectionAssert.AreEqual(Random, ReadAll(mpq, @"data\new.bin"));
            CollectionAssert.Contains(ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)), @"data\new.bin");
        }
        foreach (var file in expected.Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096, files);
    }

    [TestMethod]
    public void AddFile_RejectsInternalNamesAndReadOnlyArchives()
    {
        using (var mpq = MpqArchive.Create(new MemoryStream()))
            Assert.ThrowsExactly<ArgumentException>(() => mpq.AddFile("(listfile)", new MemoryStream([1])));

        using var readOnly = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        Assert.ThrowsExactly<InvalidOperationException>(() => readOnly.AddFile("x.txt", new MemoryStream([1])));
    }

    /// <summary>StormLib strips MPQ_FILE_SINGLE_UNIT in archives it creates as v1; so does this library.</summary>
    [TestMethod]
    public void AddFile_SingleUnitIsIgnoredForCreatedV1()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text), new MpqAddFileOptions { SingleUnit = true });

        stream.Position = 0;
        using var reopened = MpqArchive.Open(stream);
        Assert.IsFalse(reopened.Entries.Single(e => e.Name == "a.txt").Flags.HasFlag(MpqFileFlags.SingleUnit));
        CollectionAssert.AreEqual(Text, ReadAll(reopened, "a.txt"));
    }

    [TestMethod]
    public void Dispose_WithoutChangesLeavesFileUntouched()
    {
        string path = Path.Combine(_directory, "copy.mpq");
        File.Copy(TestDataPath.Get("v1-zlib.mpq"), path);
        byte[] before = File.ReadAllBytes(path);

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
            _ = ReadAll(mpq, "readme.txt");

        CollectionAssert.AreEqual(before, File.ReadAllBytes(path));
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

    private static byte[] CreateSparse(int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i += 997)
            data[i] = (byte)(i % 251 + 1);
        return data;
    }

    /// <summary>16-bit PCM, 0.5 s, 440 Hz (no RIFF header needed for the codec).</summary>
    private static byte[] CreateSine(int channels)
    {
        const int samples = 11025;
        var data = new byte[samples * channels * 2];
        for (int i = 0; i < samples; i++)
        {
            short value = (short)(Math.Sin(2 * Math.PI * 440 * i / 22050) * 12000);
            for (int c = 0; c < channels; c++)
                System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan((i * channels + c) * 2), value);
        }
        return data;
    }
}
