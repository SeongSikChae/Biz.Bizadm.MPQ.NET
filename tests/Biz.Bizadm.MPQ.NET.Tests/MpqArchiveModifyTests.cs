using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveModifyTests
{
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-modify-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));
    private static readonly byte[] Random = CreateRandom(50000);

    [TestMethod]
    [DataRow("v1-zlib.mpq")]
    [DataRow("v2-bzip2.mpq")]
    [DataRow("v3-lzma.mpq")]
    [DataRow("v4-mixed.mpq")]
    public void DeleteFile_RemovesOnlyThatFile(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        var userFiles = expected.Files.Where(f => !f.Internal).ToList();
        string deleted = userFiles[0].Name;
        string path = Copy(archive);

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.DeleteFile(deleted);
            Assert.IsFalse(mpq.Contains(deleted));
        }

        var files = ReadExpected(path, userFiles.Skip(1));
        using (var mpq = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true }))
        {
            Assert.IsFalse(mpq.Contains(deleted));
            CollectionAssert.DoesNotContain(ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)), deleted);
            Assert.IsFalse(mpq.Entries.Any(e => e.Name == deleted));
        }
        StormLibVerifier.AssertStormLibReads(path, (MpqFormatVersion)expected.FormatVersion, expected.SectorSize, files);
    }

    [TestMethod]
    public void DeleteFile_ThenAddSameName()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text));
        using (var mpq = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true))
        {
            mpq.DeleteFile("a.txt");
            mpq.AddFile("a.txt", new MemoryStream(Random));
        }
        using var reopened = MpqArchive.Open(stream);
        CollectionAssert.AreEqual(Random, ReadAll(reopened, "a.txt"));
        Assert.AreEqual(1, reopened.Entries.Count(e => e.Name == "a.txt"));
    }

    [TestMethod]
    public void DeleteAndRename_RejectInvalidRequests()
    {
        using var mpq = MpqArchive.Create(new MemoryStream());
        mpq.AddFile("a.txt", new MemoryStream(Text));
        mpq.AddFile("b.txt", new MemoryStream(Text));

        Assert.ThrowsExactly<FileNotFoundException>(() => mpq.DeleteFile("missing.txt"));
        Assert.ThrowsExactly<FileNotFoundException>(() => mpq.RenameFile("missing.txt", "c.txt"));
        Assert.ThrowsExactly<ArgumentException>(() => mpq.DeleteFile(ListFile.ListFileName));
        Assert.ThrowsExactly<ArgumentException>(() => mpq.RenameFile("a.txt", ListFile.AttributesName));
        Assert.ThrowsExactly<InvalidOperationException>(() => mpq.RenameFile("a.txt", "b.txt"));

        using var readOnly = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        Assert.ThrowsExactly<InvalidOperationException>(() => readOnly.DeleteFile("readme.txt"));
    }

    /// <summary>Data is never overwritten in place, so streams opened before a delete or rename keep reading.</summary>
    [TestMethod]
    public void OpenStream_KeepsReadingAfterDeleteAndRename()
    {
        string path = Path.Combine(_directory, "streams.mpq");
        var encrypted = new MpqAddFileOptions { Encrypt = true, FixKey = true };
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("deleted.bin", new MemoryStream(Random));
            mpq.AddFile("renamed.bin", new MemoryStream(Random), encrypted);
        }

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            using var deleted = mpq.OpenFile("deleted.bin");
            using var renamed = mpq.OpenFile("renamed.bin");
            var head = new byte[100];
            deleted.ReadExactly(head);
            renamed.ReadExactly(head);

            mpq.DeleteFile("deleted.bin");
            mpq.RenameFile("renamed.bin", @"moved\other.bin");
            mpq.Flush();

            CollectionAssert.AreEqual(Random, ReadFrom(deleted, 0));
            CollectionAssert.AreEqual(Random, ReadFrom(renamed, 0));
            CollectionAssert.AreEqual(Random, ReadAll(mpq, @"moved\other.bin"));
        }
    }

    /// <summary>New data is not written over a deleted file that an open stream still reads.</summary>
    [TestMethod]
    public void OpenStream_DeletedLastFileIsNotOverwritten()
    {
        using var archive = new MemoryStream();
        using (var mpq = MpqArchive.Create(archive, leaveOpen: true))
            mpq.AddFile("last.bin", new MemoryStream(Random), new MpqAddFileOptions { Compression = MpqCompressionType.None });

        using var opened = MpqArchive.Open(archive, MpqOpenMode.ReadWrite, leaveOpen: true);
        using var stream = opened.OpenFile("last.bin");
        opened.DeleteFile("last.bin");
        opened.AddFile("new.bin", new MemoryStream(Text));
        opened.Flush();

        CollectionAssert.AreEqual(Random, ReadFrom(stream, 0));
        CollectionAssert.AreEqual(Text, ReadAll(opened, "new.bin"));
    }

    [TestMethod]
    public void DeleteFile_DoesNotTouchPatchFiles()
    {
        string path = Copy("patch-1.mpq");
        using var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite);
        string patchFile = mpq.Entries.First(e => e.Flags.HasFlag(MpqFileFlags.PatchFile) && e.Name is not null).Name!;
        Assert.ThrowsExactly<FileNotFoundException>(() => mpq.DeleteFile(patchFile));
        Assert.ThrowsExactly<FileNotFoundException>(() => mpq.RenameFile(patchFile, "other.bin"));
    }

    /// <summary>
    /// Compacting an unchanged archive whose block table has unused entries rewrites (attributes) for the new block
    /// order, so CRC32/MD5 still belong to the right files.
    /// </summary>
    [TestMethod]
    public void Compact_UnusedBlockEntriesKeepAttributesAligned()
    {
        using var archive = new MemoryStream();
        using (var mpq = MpqArchive.Create(archive, leaveOpen: true))
        {
            mpq.AddFile("a.bin", new MemoryStream(Random));
            mpq.AddFile("b.txt", new MemoryStream(Text));
            mpq.AddFile("c.bin", new MemoryStream(CreateRandom(3000)));
        }

        // Clear MPQ_FILE_EXISTS of the first block, as another tool could leave it.
        var (header, _, _) = MpqHeaderReader.Find(archive);
        var blocks = new byte[header.BlockTableSize * 16];
        archive.Position = header.BlockTablePosition;
        archive.ReadExactly(blocks);
        StormCrypto.DecryptBlock(blocks.AsSpan(), StormCrypto.BlockTableKey);
        uint flags = BitConverter.ToUInt32(blocks, 12);
        BitConverter.TryWriteBytes(blocks.AsSpan(12), flags & ~(uint)MpqFileFlags.Exists);
        StormCrypto.EncryptBlock(blocks.AsSpan(), StormCrypto.BlockTableKey);
        archive.Position = header.BlockTablePosition;
        archive.Write(blocks);

        using (var mpq = MpqArchive.Open(archive, MpqOpenMode.ReadWrite, leaveOpen: true))
            mpq.Compact();

        using var reopened = MpqArchive.Open(archive, leaveOpen: true);
        var (newHeader, _, offset) = MpqHeaderReader.Find(archive);
        var table = MpqFileTable.Load(archive, newHeader, offset);
        MpqAttributes.Apply(ReadAll(reopened, ListFile.AttributesName), (int)newHeader.BlockTableSize, table.Entries);
        foreach (string name in new[] { "b.txt", "c.bin" })
        {
            byte[] data = ReadAll(reopened, name);
            var entry = table.Entries.Single(e => e.FilePosition == table.Find(name)!.FilePosition);
            Assert.AreEqual(Crc32.Compute(data), entry.Crc32, name);
            CollectionAssert.AreEqual(MD5.HashData(data), entry.Md5, name);
        }
        Assert.IsFalse(reopened.Contains("a.bin"));
    }

    public static IEnumerable<object[]> RenameCases =>
    [
        ["plain", false, false, MpqFormatVersion.Version2],
        ["encrypted", true, false, MpqFormatVersion.Version2],
        ["encrypted-fixkey", true, true, MpqFormatVersion.Version2],
        ["encrypted-fixkey-v4", true, true, MpqFormatVersion.Version4],
    ];

    /// <summary>Encrypted files are re-encrypted with the key of the new name (and position for KEY_V2).</summary>
    [TestMethod]
    [DynamicData(nameof(RenameCases))]
    public void RenameFile_KeepsContentAndLocale(string name, bool encrypt, bool fixKey, MpqFormatVersion version)
    {
        string path = Path.Combine(_directory, name + ".mpq");
        MpqAddFileOptions Options(ushort locale = 0, bool singleUnit = false, MpqCompressionType compression = MpqCompressionType.Zlib) =>
            new() { Encrypt = encrypt, FixKey = fixKey, SectorCrc = true, Locale = locale, SingleUnit = singleUnit, Compression = compression };
        using (var mpq = MpqArchive.Create(path, new MpqArchiveCreateOptions { FormatVersion = version }))
        {
            mpq.AddFile(@"data\random.bin", new MemoryStream(Random), Options());
            // A file only in another locale is not found by the neutral-locale rename and stays untouched.
            mpq.AddFile("readme.txt", new MemoryStream(Text), Options(locale: 0x409));
            mpq.AddFile("single.txt", new MemoryStream(Text), Options(singleUnit: true));
            mpq.AddFile("raw.bin", new MemoryStream(Random), Options(compression: MpqCompressionType.None));
        }

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.RenameFile(@"data\random.bin", @"other\renamed.bin");
            mpq.RenameFile("single.txt", "single2.txt");
            mpq.RenameFile("raw.bin", "raw2.bin");
            // Lookups accept both separators.
            mpq.RenameFile("other/renamed.bin", "final.bin");
        }

        var files = new Dictionary<string, byte[]>
        {
            ["final.bin"] = Random,
            ["single2.txt"] = Text,
            ["raw2.bin"] = Random,
        };
        using (var mpq = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true }))
        {
            foreach (string old in new[] { @"data\random.bin", @"other\renamed.bin", "single.txt", "raw.bin" })
                Assert.IsFalse(mpq.Contains(old), old);
            foreach (var (fileName, data) in files)
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
            CollectionAssert.AreEquivalent(new[] { "final.bin", "single2.txt", "raw2.bin", "readme.txt" },
                ListFile.Parse(ReadAll(mpq, ListFile.ListFileName)));
        }

        StormLibVerifier.AssertStormLibReads(path, version, 4096, files);
    }

    [TestMethod]
    [DataRow("v1-encrypted.mpq")]
    public void RenameFile_EncryptedFixtureFiles(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        var userFiles = expected.Files.Where(f => !f.Internal).ToList();
        string path = Copy(archive);
        var renamed = new Dictionary<string, string>();
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            foreach (var file in userFiles.Where(f => ((MpqFileFlags)f.Flags).HasFlag(MpqFileFlags.Encrypted)))
            {
                string newName = @"renamed\" + Path.GetFileName(file.Name.Replace('\\', '/')) + ".new";
                mpq.RenameFile(file.Name, newName);
                renamed[file.Name] = newName;
            }
        }
        Assert.AreNotEqual(0, renamed.Count, "the fixture has encrypted files");

        var files = new Dictionary<string, byte[]>();
        using (var mpq = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true }))
        {
            foreach (var file in userFiles)
            {
                string name = renamed.GetValueOrDefault(file.Name, file.Name);
                files[name] = ReadAll(mpq, name);
                Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[name])), name);
            }
        }
        StormLibVerifier.AssertStormLibReads(path, (MpqFormatVersion)expected.FormatVersion, expected.SectorSize, files);
    }

    [TestMethod]
    [DataRow(MpqFormatVersion.Version1)]
    [DataRow(MpqFormatVersion.Version2)]
    [DataRow(MpqFormatVersion.Version3)]
    [DataRow(MpqFormatVersion.Version4)]
    public void Compact_RemovesUnusedSpace(MpqFormatVersion version)
    {
        string path = Path.Combine(_directory, $"compact-{version}.mpq");
        var encrypted = new MpqAddFileOptions { Encrypt = true, FixKey = true };
        using (var mpq = MpqArchive.Create(path, new MpqArchiveCreateOptions { FormatVersion = version }))
        {
            mpq.AddFile("deleted.bin", new MemoryStream(Random));
            mpq.AddFile("replaced.bin", new MemoryStream(Random));
            mpq.AddFile("keyv2.bin", new MemoryStream(Random), encrypted);
            mpq.AddFile("readme.txt", new MemoryStream(Text), new MpqAddFileOptions { SectorCrc = true });
        }
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.DeleteFile("deleted.bin");
            mpq.AddFile("replaced.bin", new MemoryStream(Text), new MpqAddFileOptions { Overwrite = true });
            mpq.Flush();
        }
        long before = new FileInfo(path).Length;

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.Compact();
            // The archive stays usable after Compact.
            CollectionAssert.AreEqual(Random, ReadAll(mpq, "keyv2.bin"));
        }

        var files = new Dictionary<string, byte[]> { ["replaced.bin"] = Text, ["keyv2.bin"] = Random, ["readme.txt"] = Text };
        Assert.IsTrue(new FileInfo(path).Length < before - Random.Length, $"{new FileInfo(path).Length} >= {before}");
        Assert.IsFalse(File.Exists(path + ".tmp"));
        using (var mpq = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true }))
        {
            Assert.AreEqual(version, mpq.Header.FormatVersion);
            Assert.IsFalse(mpq.Contains("deleted.bin"));
            foreach (var (fileName, data) in files)
                CollectionAssert.AreEqual(data, ReadAll(mpq, fileName), fileName);
        }
        StormLibVerifier.AssertStormLibReads(path, version, 4096, files);
    }

    /// <summary>Data before the archive and SC2 user data are kept; an archive opened from a stream is overwritten.</summary>
    [TestMethod]
    public void Compact_StreamKeepsUserData()
    {
        var expected = ExpectedArchive.Load("sc2-userdata.SC2Replay");
        byte[] original = File.ReadAllBytes(TestDataPath.Get("sc2-userdata.SC2Replay"));
        var stream = new MemoryStream();
        stream.Write(original);
        string first = expected.Files.First(f => !f.Internal).Name;

        MpqUserData userData;
        using (var mpq = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true))
        {
            userData = mpq.UserData!;
            mpq.DeleteFile(first);
            mpq.Compact();
        }

        var files = new Dictionary<string, byte[]>();
        using (var mpq = MpqArchive.Open(stream, leaveOpen: true))
        {
            CollectionAssert.AreEqual(userData.Content.ToArray(), mpq.UserData!.Content.ToArray());
            Assert.AreEqual(userData.HeaderOffset, mpq.UserData.HeaderOffset);
            foreach (var file in expected.Files.Where(f => !f.Internal && f.Name != first))
            {
                files[file.Name] = ReadAll(mpq, file.Name);
                Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);
            }
        }

        string path = Path.Combine(_directory, "compacted.SC2Replay");
        File.WriteAllBytes(path, stream.ToArray());
        StormLibVerifier.AssertStormLibReads(path, (MpqFormatVersion)expected.FormatVersion, expected.SectorSize, files);
    }

    [TestMethod]
    public void Compact_RejectsOpenStreamsAndUnknownNames()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, new MpqArchiveCreateOptions { CreateListFile = false }, leaveOpen: true))
            mpq.AddFile("a.txt", new MemoryStream(Text));

        using var opened = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true);
        Assert.ThrowsExactly<InvalidOperationException>(opened.Compact);
        opened.AddListFile(["a.txt"]);

        var file = opened.OpenFile("a.txt");
        Assert.ThrowsExactly<InvalidOperationException>(opened.Compact);
        file.Dispose();

        opened.Compact();
        CollectionAssert.AreEqual(Text, ReadAll(opened, "a.txt"));
    }

    private string Copy(string archive)
    {
        string path = Path.Combine(_directory, archive);
        File.Copy(TestDataPath.Get(archive), path);
        return path;
    }

    private static Dictionary<string, byte[]> ReadExpected(string path, IEnumerable<ExpectedFile> expected)
    {
        var files = new Dictionary<string, byte[]>();
        using var mpq = MpqArchive.Open(path);
        foreach (var file in expected)
        {
            files[file.Name] = ReadAll(mpq, file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(files[file.Name])), file.Name);
        }
        return files;
    }

    private static byte[] ReadFrom(Stream stream, long position)
    {
        stream.Position = position;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
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
