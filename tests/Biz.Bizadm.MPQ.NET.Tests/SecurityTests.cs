using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;
using Biz.Bizadm.MPQ.NET.Internal.Patch;

namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>
/// Crafted archives must fail with <see cref="InvalidDataException"/> without allocating memory out of proportion to
/// their size, and writes must not lose data or touch other files.
/// </summary>
[TestClass]
public sealed class SecurityTests
{
    // Every crafted input below would allocate at least 1 GB without the limits.
    private const long AllocationLimit = 64 * 1024 * 1024;

    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-security-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));

    [TestMethod]
    [DataRow(16)]
    [DataRow(21)]
    [DataRow(22)]
    [DataRow(23)]
    public void SectorSizeShift_AboveSixteenMegabytes_IsRejected(int shift)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v1-zlib.mpq"));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0E), (ushort)shift);
        AssertInvalidWithoutAllocation(() => MpqArchive.Open(new MemoryStream(data)).Dispose());
    }

    /// <summary>A single-unit file is one buffer; its size comes from the block table.</summary>
    [TestMethod]
    [DataRow(0x7FFFFFC0u)]
    [DataRow(0x80000000u)]
    [DataRow(0xFFFFFFFFu)]
    public void SingleUnitFileSize_AboveTheBufferLimit_IsRejected(uint fileSize)
    {
        byte[] data = CreateArchive(new MpqArchiveCreateOptions { FormatVersion = MpqFormatVersion.Version2 }, "big.bin", Text,
            new MpqAddFileOptions { SingleUnit = true });
        RewriteBlock(data, "big.bin", entry => BinaryPrimitives.WriteUInt32LittleEndian(entry[8..], fileSize));

        using var mpq = MpqArchive.Open(new MemoryStream(data));
        AssertInvalidWithoutAllocation(() => mpq.OpenFile("big.bin").Dispose());
    }

    [TestMethod]
    public void MaxBufferSize_LimitsSingleUnitFiles()
    {
        byte[] data = CreateArchive(new MpqArchiveCreateOptions { FormatVersion = MpqFormatVersion.Version2 }, "a.txt", Text,
            new MpqAddFileOptions { SingleUnit = true });
        using (var mpq = MpqArchive.Open(new MemoryStream(data), options: new MpqOpenOptions { MaxBufferSize = 1024 }))
            Assert.ThrowsExactly<InvalidDataException>(() => mpq.OpenFile("a.txt"));
        using (var mpq = MpqArchive.Open(new MemoryStream(data)))
            CollectionAssert.AreEqual(Text, ReadAll(mpq, "a.txt"));
    }

    /// <summary>The 76-byte v2 file from the review: a block table of 0xFFFFFF entries past the end of the file.</summary>
    [TestMethod]
    public void BlockTableSize_FromTinyFile_IsRejected()
    {
        var data = new byte[0x4C];
        BinaryPrimitives.WriteUInt32LittleEndian(data, MpqHeaderReader.HeaderSignature);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x2C);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x08), 0x1000); // not the file size: the table is not "compressed"
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0C), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0E), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), 0x2C);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14), 0x3C);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x18), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x1C), 0x00FFFFFF);
        AssertInvalidWithoutAllocation(() => MpqArchive.Open(new MemoryStream(data)).Dispose());
    }

    /// <summary>The 100-byte v3 file from the review: a HET table that claims 2 GB of data.</summary>
    [TestMethod]
    public void HetDataSize_IsRejected()
    {
        var data = new byte[0x64];
        BinaryPrimitives.WriteUInt32LittleEndian(data, MpqHeaderReader.HeaderSignature);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x44);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0C), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0E), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x2C), 0x64);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x3C), 0x44);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x44), MpqTableReader.HetSignature);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x48), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x4C), 0x7FFFFF00);
        AssertInvalidWithoutAllocation(() => MpqArchive.Open(new MemoryStream(data)).Dispose());
    }

    /// <summary>Hi-block positions outside the file fail as invalid data, not with stream exceptions.</summary>
    [TestMethod]
    [DataRow(0x8000000000000000ul)]
    [DataRow(0ul)]
    public void HiBlockTablePosition_OutsideTheFile_IsInvalidData(ulong position)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v2-bzip2.mpq"));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x20), position == 0 ? (ulong)data.Length : position);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(data)).Dispose());
    }

    /// <summary>A forged hi-block table moves files outside the file; such an archive must not be modified.</summary>
    [TestMethod]
    public void ForgedHiBlockTable_MakesTheArchiveReadOnly()
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v2-bzip2.mpq"));
        var hi = new byte[BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x1C)) * 2];
        for (int i = 0; i < hi.Length; i += 2)
            BinaryPrimitives.WriteUInt16LittleEndian(hi.AsSpan(i), 0x7FFF);
        byte[] forged = [.. data, .. hi];
        BinaryPrimitives.WriteUInt64LittleEndian(forged.AsSpan(0x20), (ulong)data.Length);

        using var mpq = MpqArchive.Open(new MemoryStream(forged), MpqOpenMode.ReadWrite);
        Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("x.txt", new MemoryStream(Text)));
        Assert.ThrowsExactly<InvalidOperationException>(mpq.Compact);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(forged), options: new MpqOpenOptions { Strict = true }));
    }

    [TestMethod]
    public void PatchSizes_AboveTheBufferLimit_AreRejected()
    {
        // BSD0 with RLE: 8 bytes of data that would decode to 2 GB.
        byte[] rle = PatchHeader(sizeOfPatchData: 0x7FFFFFC0, sizeAfter: 0x20, xfrmBlockSize: 20, type: 0x30445342, body: new byte[8]);
        AssertInvalidWithoutAllocation(() => MpqPatch.ApplyChain(new byte[0x20], null, [rle], 0x20));

        // BSD0 whose new file size is near 4 GB.
        var bsdiff = new byte[0x20];
        "BSDIFF40"u8.CopyTo(bsdiff);
        BinaryPrimitives.WriteUInt64LittleEndian(bsdiff.AsSpan(0x18), 0xFFFFFFF0);
        byte[] huge = PatchHeader(sizeOfPatchData: (uint)(0x44 + bsdiff.Length), sizeAfter: 0xFFFFFFF0,
            xfrmBlockSize: (uint)(0x0C + bsdiff.Length), type: 0x30445342, body: bsdiff);
        AssertInvalidWithoutAllocation(() => MpqPatch.ApplyChain(new byte[0x20], null, [huge], 0xFFFFFFF0));
    }

    /// <summary>
    /// A hash table without free slots would make every name lookup walk the whole table; with the lookup index,
    /// applying many names stays fast, so even strict opening succeeds.
    /// </summary>
    [TestMethod]
    [Timeout(30_000)]
    public void HashTableWithoutFreeSlots_DoesNotMakeNamesQuadratic()
    {
        byte[] data = CreateArchive(new MpqArchiveCreateOptions { FormatVersion = MpqFormatVersion.Version3, HashTableSize = 0x10000 },
            "a.txt", Text, new MpqAddFileOptions());
        uint hashPos = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x10));
        uint hashSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x18));
        var table = data.AsSpan((int)hashPos, (int)hashSize * 16);
        StormCrypto.DecryptBlock(table, StormCrypto.HashTableKey);
        for (int i = 0; i < hashSize; i++)
        {
            var blockIndex = table.Slice(i * 16 + 12, 4);
            if (BinaryPrimitives.ReadUInt32LittleEndian(blockIndex) == MpqHashEntry.Free)
                BinaryPrimitives.WriteUInt32LittleEndian(blockIndex, MpqHashEntry.Deleted);
        }
        StormCrypto.EncryptBlock(table, StormCrypto.HashTableKey);
        var names = Enumerable.Range(0, 100_000).Select(i => $"missing{i}.txt").ToList();

        using var mpq = MpqArchive.Open(new MemoryStream(data), options: new MpqOpenOptions { ExternalListFile = names, Strict = true });
        CollectionAssert.AreEqual(Text, ReadAll(mpq, "a.txt"));
        Assert.IsFalse(mpq.Contains("missing1.txt"));
    }

    /// <summary>The lookup indexes give the same answers as walking the probe chains, also after slots change.</summary>
    [TestMethod]
    public void LookupIndexes_MatchProbing()
    {
        var random = new Random(11);
        for (int round = 0; round < 40; round++)
        {
            int size = 1 << random.Next(2, 7);
            var names = Enumerable.Range(0, size * 2).Select(i => $"file{round}_{i}.txt").ToList();
            var hash = new MpqHashEntry[size];
            for (int i = 0; i < size; i++)
            {
                int kind = random.Next(4);
                string name = names[random.Next(names.Count)];
                hash[i] = kind == 0
                    ? new MpqHashEntry(MpqHashEntry.Free, MpqHashEntry.Free, 0xFFFF, 0xFF, 0xFF, MpqHashEntry.Free)
                    : new MpqHashEntry(StormCrypto.HashStringSlash(name, MpqHashType.NameA), StormCrypto.HashStringSlash(name, MpqHashType.NameB),
                        (ushort)(random.Next(3) == 0 ? 0x409 : 0), (byte)(random.Next(5) == 0 ? 1 : 0), 0,
                        kind == 1 ? MpqHashEntry.Deleted : (uint)random.Next(size + 2));
            }
            var entries = Enumerable.Range(0, size).Select(_ => new MpqFileEntry { Flags = MpqFileFlags.Exists }).ToArray();
            var table = new MpqFileTable(hash, entries);

            for (int step = 0; step < 3; step++)
            {
                foreach (string name in names)
                {
                    uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & (uint)(size - 1);
                    uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA), b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
                    foreach (var (locale, platform) in new (ushort, byte)[] { (0, 0), (0x409, 0), (0x409, 1), (0, 1) })
                        Assert.AreEqual(table.ProbeSlot(start, a, b, locale, platform), table.FindSlotIndexed(start, a, b, locale, platform), name);
                }
                // Change slots through the table, so the index is updated incrementally.
                int slot = random.Next(size);
                if (random.Next(2) == 0)
                    table.DeleteSlot(slot);
                else
                    table.SetSlot(slot, names[random.Next(names.Count)], 0, random.Next(size));
            }
        }

        // HET: compare with the probe on a table built from entries with random name hashes.
        for (int round = 0; round < 20; round++)
        {
            var entries = Enumerable.Range(0, random.Next(1, 200)).Select(i => new MpqFileEntry
            {
                Flags = random.Next(4) == 0 ? 0 : MpqFileFlags.Exists,
                NameHash = (ulong)random.NextInt64() | 0x8000000000000000,
            }).ToList();
            var het = HetTable.Build(entries);
            foreach (var entry in entries.Concat([new MpqFileEntry { NameHash = 0x8123456789ABCDEF }]))
                Assert.AreEqual(het.ProbeIndex(entry.NameHash, entries), het.FindIndex(entry.NameHash, entries));
        }
    }

    /// <summary>Changes that were never flushed (a crash) leave the archive on disk as it was.</summary>
    [TestMethod]
    public void InterruptedChange_KeepsTheArchiveOnDisk()
    {
        var expected = ExpectedArchive.Load("v1-zlib.mpq");
        string path = Path.Combine(_directory, "crash.mpq");
        File.Copy(TestDataPath.Get("v1-zlib.mpq"), path);

        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            var mpq = MpqArchive.Open(stream, MpqOpenMode.ReadWrite, leaveOpen: true);
            mpq.AddFile("new.bin", new MemoryStream(new byte[100_000]));
            mpq.DeleteFile(expected.Files.First(f => !f.Internal).Name);
            // The process "dies": the archive is never flushed or disposed.
        }

        using var reopened = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true });
        foreach (var file in expected.Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(reopened, file.Name))), file.Name);
        Assert.IsFalse(reopened.Contains("new.bin"));
    }

    /// <summary>Compact uses a new temporary file with a random name and leaves nothing behind.</summary>
    [TestMethod]
    public void Compact_DoesNotTouchOtherFiles()
    {
        string path = Path.Combine(_directory, "a.mpq");
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("a.txt", new MemoryStream(Text));
            mpq.AddFile("b.txt", new MemoryStream(Text));
        }
        File.WriteAllText(path + ".tmp", "IMPORTANT USER DATA");

        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.DeleteFile("b.txt");
            mpq.Compact();
        }

        Assert.AreEqual("IMPORTANT USER DATA", File.ReadAllText(path + ".tmp"));
        CollectionAssert.AreEquivalent(new[] { "a.mpq", "a.mpq.tmp" }, Directory.GetFiles(_directory).Select(Path.GetFileName).ToList());
        using var reopened = MpqArchive.Open(path, options: new MpqOpenOptions { Strict = true });
        CollectionAssert.AreEqual(Text, ReadAll(reopened, "a.txt"));
    }

    /// <summary>Names that would split a (listfile) line, or that look like StormLib pseudo names, are rejected.</summary>
    [TestMethod]
    [DataRow("a.txt\r\nb.txt")]
    [DataRow("a\nb")]
    [DataRow("a\0b")]
    [DataRow("File00000001.txt")]
    public void FileNames_ThatCannotBeStored_AreRejected(string name)
    {
        using var mpq = MpqArchive.Create(new MemoryStream());
        Assert.ThrowsExactly<ArgumentException>(() => mpq.AddFile(name, new MemoryStream(Text)));
        mpq.AddFile("ok.txt", new MemoryStream(Text));
        Assert.ThrowsExactly<ArgumentException>(() => mpq.RenameFile("ok.txt", name));
    }

    /// <summary>A large "-PATCH" helper file is not read.</summary>
    [TestMethod]
    public void LargePatchHelperFile_IsNotRead()
    {
        string basePath = Path.Combine(_directory, "x.SC2Data");
        using (var mpq = MpqArchive.Create(basePath))
            mpq.AddFile("StreamingBuckets.txt", new MemoryStream(Text));
        string patchPath = Path.Combine(_directory, "patch.mpq");
        using (var mpq = MpqArchive.Create(patchPath))
            mpq.AddFile(@"Foo\(patch_metadata)", new MemoryStream(Text));
        using (var helper = File.Create(basePath + "-PATCH"))
        {
            helper.Write("PatchPrefix=Foo\r\n"u8);
            helper.SetLength(64 * 1024 * 1024);
        }

        using var archive = MpqArchive.Open(basePath);
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.ThrowsExactly<InvalidOperationException>(() => archive.OpenPatchArchive(patchPath));
        Assert.IsTrue(GC.GetAllocatedBytesForCurrentThread() - before < 32 * 1024 * 1024);
    }

    /// <summary>A zeroed (signature) is reported as unsigned, not as a valid weak signature.</summary>
    [TestMethod]
    public void ZeroedWeakSignature_IsUnsigned()
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get("v1-weak-signed.mpq"));
        using (var stream = new MemoryStream(data))
        {
            var (header, _, offset) = MpqHeaderReader.Find(stream);
            var table = MpqFileTable.Load(stream, header, offset);
            data.AsSpan((int)(offset + table.Find(ListFile.SignatureName)!.FilePosition), MpqSignature.FileSize).Clear();
        }
        using var mpq = MpqArchive.Open(new MemoryStream(data));
        Assert.AreEqual(MpqSignatureStatus.WeakUnsigned, mpq.VerifySignature());
    }

    private static void AssertInvalidWithoutAllocation(Action action)
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.ThrowsExactly<InvalidDataException>(action);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.IsTrue(allocated < AllocationLimit, $"allocated {allocated} bytes");
    }

    private static byte[] CreateArchive(MpqArchiveCreateOptions options, string name, byte[] content, MpqAddFileOptions fileOptions)
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, options, leaveOpen: true))
            mpq.AddFile(name, new MemoryStream(content), fileOptions);
        return stream.ToArray();
    }

    private static void RewriteBlock(byte[] data, string name, Action<Span<byte>> change)
    {
        int block;
        using (var mpq = MpqArchive.Open(new MemoryStream(data)))
            block = mpq.Entries.Single(e => e.Name == name).BlockIndex;
        uint blockPos = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x14));
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x1C));
        var table = data.AsSpan((int)blockPos, (int)blocks * 16);
        StormCrypto.DecryptBlock(table, StormCrypto.BlockTableKey);
        change(table.Slice(block * 16, 16));
        StormCrypto.EncryptBlock(table, StormCrypto.BlockTableKey);
    }

    private static byte[] PatchHeader(uint sizeOfPatchData, uint sizeAfter, uint xfrmBlockSize, uint type, byte[] body)
    {
        var patch = new byte[MpqPatch.HeaderSize + body.Length];
        var span = patch.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, 0x48435450);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x04..], sizeOfPatchData);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], sizeAfter);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x10..], 0x5F35444D);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x38..], 0x4D524658);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x3C..], xfrmBlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x40..], type);
        body.CopyTo(span[MpqPatch.HeaderSize..]);
        return patch;
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
