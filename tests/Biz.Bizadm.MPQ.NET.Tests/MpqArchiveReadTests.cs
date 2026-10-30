using System.Security.Cryptography;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqArchiveReadTests
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
    public void OpenFile_ReadsEveryFileLikeStormLib(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        using var mpq = MpqArchive.Open(TestDataPath.Get(archive));

        foreach (var file in expected.Files)
        {
            using var stream = mpq.OpenFile(file.Name);
            Assert.AreEqual(file.Size, stream.Length, file.Name);
            Assert.AreEqual(file.Sha256, Sha256(stream), file.Name);
        }
    }

    [TestMethod]
    public void Open_FromStreamHonorsLeaveOpen()
    {
        using var file = File.OpenRead(TestDataPath.Get("v1-zlib.mpq"));

        using (var mpq = MpqArchive.Open(file, leaveOpen: true))
            Assert.IsTrue(mpq.Contains("readme.txt"));
        Assert.IsTrue(file.CanRead, "leaveOpen: true must keep the stream open.");

        MpqArchive.Open(file, leaveOpen: false).Dispose();
        Assert.IsFalse(file.CanRead, "leaveOpen: false must dispose the stream.");
    }

    /// <summary>StormLib shares read access for writable archives too.</summary>
    [TestMethod]
    public void Open_ReadWriteAllowsOtherReaders()
    {
        string copy = Path.Combine(Path.GetTempPath(), $"mpq-{Guid.NewGuid():N}.mpq");
        File.Copy(TestDataPath.Get("v1-zlib.mpq"), copy);
        try
        {
            using var mpq = MpqArchive.Open(copy, MpqOpenMode.ReadWrite);
            // A reader must allow write sharing because the archive handle has write access.
            using var file = new FileStream(copy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = MpqArchive.Open(file);
            Assert.IsTrue(reader.Contains("readme.txt"));
        }
        finally
        {
            File.Delete(copy);
        }
    }

    [TestMethod]
    public void Open_RejectsReadWriteOnReadOnlyStream()
    {
        using var file = File.OpenRead(TestDataPath.Get("v1-zlib.mpq"));
        Assert.ThrowsExactly<ArgumentException>(() => MpqArchive.Open(file, MpqOpenMode.ReadWrite, leaveOpen: true));
    }

    [TestMethod]
    public void OpenFile_SeeksAndReadsPartially()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        byte[] all = ReadAll(mpq.OpenFile("readme.txt"));
        using var stream = mpq.OpenFile("readme.txt");
        var random = new Random(42);

        for (int i = 0; i < 200; i++)
        {
            int position = random.Next(all.Length);
            int count = random.Next(1, 9000);
            if (i % 2 == 0)
                stream.Seek(position, SeekOrigin.Begin);
            else
                stream.Seek(position - stream.Position, SeekOrigin.Current);
            Assert.AreEqual(position, stream.Position);
            var buffer = new byte[count];
            int read = stream.ReadAtLeast(buffer, count, throwOnEndOfStream: false);

            Assert.AreEqual(Math.Min(count, all.Length - position), read);
            CollectionAssert.AreEqual(all[position..(position + read)], buffer[..read]);
        }

        stream.Seek(-10, SeekOrigin.End);
        Assert.AreEqual(all.Length - 10, stream.Position);
        stream.Seek(100, SeekOrigin.End);
        Assert.AreEqual(0, stream.Read(new byte[10]));
        Assert.ThrowsExactly<IOException>(() => stream.Seek(-1, SeekOrigin.Begin));
    }

    [TestMethod]
    public void OpenFile_SupportsConcurrentReads()
    {
        var expected = ExpectedArchive.Load("v1-encrypted.mpq");
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-encrypted.mpq"));
        var work = Enumerable.Range(0, 64).Select(i => expected.Files[i % expected.Files.Count]).ToArray();
        var failures = new System.Collections.Concurrent.ConcurrentBag<string>();

        Parallel.ForEach(work, new ParallelOptions { MaxDegreeOfParallelism = 8 }, file =>
        {
            using var stream = mpq.OpenFile(file.Name);
            if (Sha256(stream) != file.Sha256)
                failures.Add(file.Name);
        });

        Assert.AreEqual(0, failures.Count, string.Join(", ", failures));
    }

    [TestMethod]
    public void OpenFile_SharedStreamsReadIndependently()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        byte[] readme = ReadAll(mpq.OpenFile("readme.txt"));
        byte[] random = ReadAll(mpq.OpenFile(@"data\random.bin"));
        using var a = mpq.OpenFile("readme.txt");
        using var b = mpq.OpenFile(@"data\random.bin");
        var bufferA = new byte[1000];
        var bufferB = new byte[1000];

        for (int offset = 0; offset < 10000; offset += 1000)
        {
            a.ReadExactly(bufferA);
            b.ReadExactly(bufferB);
            CollectionAssert.AreEqual(readme[offset..(offset + 1000)], bufferA);
            CollectionAssert.AreEqual(random[offset..(offset + 1000)], bufferB);
        }
    }

    [TestMethod]
    public void Contains_AndOpenFile_AcceptBothSeparators()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));

        Assert.IsTrue(mpq.Contains("data/random.bin"));
        Assert.IsTrue(mpq.Contains(@"text\slash.txt"));
        Assert.IsFalse(mpq.Contains("missing.txt"));
        Assert.AreEqual(3, ReadAll(mpq.OpenFile(@"text\slash.txt")).Length);
        Assert.ThrowsExactly<FileNotFoundException>(() => mpq.OpenFile("missing.txt"));
    }

    [TestMethod]
    public void OpenFile_ReadsEmptyFile()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        using var stream = mpq.OpenFile(@"data\empty.txt");

        Assert.AreEqual(0, stream.Length);
        Assert.AreEqual(0, stream.Read(new byte[16]));
    }

    [TestMethod]
    public void Entries_ListsExistingBlocks()
    {
        var expected = ExpectedArchive.Load("v1-zlib.mpq");
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        var entries = mpq.Entries.ToList();

        Assert.AreEqual(expected.Files.Count, entries.Count);
        CollectionAssert.AreEquivalent(
            expected.Files.Select(f => (long)f.Size).ToList(),
            entries.Select(e => e.FileSize).ToList());
        Assert.IsTrue(entries.All(e => e.Flags.HasFlag(MpqFileFlags.Exists)));
    }

    [TestMethod]
    public void Open_ExposesHeaderAndUserData()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("sc2-userdata.SC2Replay"));

        Assert.AreEqual(MpqFormatVersion.Version2, mpq.Header.FormatVersion);
        Assert.IsNotNull(mpq.UserData);
        Assert.AreEqual(0x400, mpq.HeaderOffset);
    }

    [TestMethod]
    public void Dispose_InvalidatesArchiveAndOpenStreams()
    {
        var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        var stream = mpq.OpenFile("readme.txt");
        mpq.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => mpq.OpenFile("readme.txt"));
        Assert.ThrowsExactly<ObjectDisposedException>(() => mpq.Contains("readme.txt"));
        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.Read(new byte[16]));
        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.Length);
        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.Position);
        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.IsFalse(stream.CanRead);
        Assert.IsFalse(stream.CanSeek);

        stream.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.Position);
    }

    [TestMethod]
    public void FileStream_IsReadOnly()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        using var stream = mpq.OpenFile("readme.txt");

        Assert.IsTrue(stream.CanRead);
        Assert.IsTrue(stream.CanSeek);
        Assert.IsFalse(stream.CanWrite);
        Assert.ThrowsExactly<NotSupportedException>(() => stream.Write(new byte[1]));
        Assert.ThrowsExactly<NotSupportedException>(() => stream.SetLength(1));
    }

    private static string Sha256(Stream stream) => Convert.ToHexString(SHA256.HashData(stream));

    private static byte[] ReadAll(Stream stream)
    {
        using (stream)
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }
    }
}
