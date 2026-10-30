using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>
/// Damaged and protected archives (StormLib ConvertMpqHeaderToFormat4, LoadMpqTable, BuildFileTableFromBlockTable):
/// repaired archives are readable by default, read-only, and rejected in strict mode.
/// </summary>
[TestClass]
public sealed class LenientReadTests
{
    private const string Archive = "v1-zlib.mpq";
    private static readonly MpqOpenOptions Strict = new() { Strict = true };

    /// <summary>A v1 header with another size is read with the 32-byte size (StormLib MPQ_FLAG_MALFORMED).</summary>
    [TestMethod]
    public void HeaderSize_IsRepaired()
    {
        byte[] data = Load();
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x40);
        AssertRepaired(data, mpq => Assert.AreEqual(0x20u, mpq.Header.HeaderSize));
    }

    /// <summary>StormLib skips signatures whose header size is below 0x20 (Warcraft III Storm.dll check).</summary>
    [TestMethod]
    public void HeaderSizeBelow0x20_IsNotAHeader()
    {
        byte[] data = Load();
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x10);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(data)));
    }

    /// <summary>Only the low byte of the sector size shift is used.</summary>
    [TestMethod]
    public void SectorSizeHighByte_IsRepaired()
    {
        byte[] data = Load();
        data[0x0F] = 0x01;
        AssertRepaired(data, mpq => Assert.AreEqual(4096, mpq.Header.SectorSize));
    }

    /// <summary>A header whose tables lie outside the file is fake; the search continues at the next 0x200 bytes.</summary>
    [TestMethod]
    public void FakeHeaderInFront_IsSkipped()
    {
        byte[] archive = Load();
        var data = new byte[0x200 + archive.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(data, MpqHeaderReader.HeaderSignature);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), 0xFFFFFF00);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14), 0xFFFFFF00);
        archive.CopyTo(data, 0x200);

        using var mpq = MpqArchive.Open(new MemoryStream(data), options: Strict);
        Assert.AreEqual(0x200, mpq.HeaderOffset);
        AssertFilesRead(mpq);
    }

    /// <summary>
    /// A v1 block table size beyond the file is cut to the file (EWIX_v8_7.w3x). StormLib does not mark this as
    /// malformed, so the archive stays valid in strict mode.
    /// </summary>
    [TestMethod]
    public void BlockTableSizeTooLarge_IsCut()
    {
        byte[] data = Load();
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x1C));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x1C), 0x00319601);

        using var mpq = MpqArchive.Open(new MemoryStream(data), options: Strict);
        Assert.AreEqual(blocks, mpq.Header.BlockTableSize);
        AssertFilesRead(mpq);
    }

    /// <summary>
    /// A hash table that runs past the end of the file is zero-filled (Spazzler protector) and the archive is malformed.
    /// The larger size also changes the lookup mask, so (like StormLib) names are generally not found any more.
    /// </summary>
    [TestMethod]
    public void HashTablePastEndOfFile_IsMalformed()
    {
        byte[] data = Load();
        uint hashSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x18));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x18), hashSize * 4);
        AssertRepaired(data, mpq => Assert.AreEqual(hashSize * 4, mpq.Header.HashTableSize), checkFiles: false);
    }

    /// <summary>A bogus hash table size does not allocate gigabytes of zeros past the end of the file.</summary>
    [TestMethod]
    public void HugeHashTableSize_IsRejected()
    {
        byte[] data = Load();
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x18), 0x07FFFFF0);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(data)));
    }

    /// <summary>
    /// A truncated v1 archive: the block table size is cut to the whole entries left in the file (not malformed in
    /// StormLib). The last block is gone, so its file is missing; the other files are read.
    /// </summary>
    [TestMethod]
    public void TruncatedBlockTable_KeepsOtherFiles()
    {
        byte[] full = Load();
        uint blockPos = BinaryPrimitives.ReadUInt32LittleEndian(full.AsSpan(0x14));
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(full.AsSpan(0x1C));
        Assert.AreEqual((long)full.Length, (long)blockPos + blocks * 16, "the block table is the end of the fixture");
        byte[] data = full[..^8];

        var lastBlockFile = FilesByBlock(full).Single(f => f.Block == blocks - 1).Name;
        using var mpq = MpqArchive.Open(new MemoryStream(data), options: Strict);
        Assert.AreEqual(blocks - 1, mpq.Header.BlockTableSize);
        Assert.IsFalse(mpq.Contains(lastBlockFile));
        foreach (var file in ExpectedArchive.Load(Archive).Files.Where(f => !f.Internal && f.Name != lastBlockFile))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, file.Name))), file.Name);
    }

    /// <summary>
    /// v2 has no block table size cut: a block table running past the end of the file is zero-filled and the archive is
    /// malformed; the zero-filled entry is not a file.
    /// </summary>
    [TestMethod]
    public void V2TruncatedBlockTable_IsZeroFilled()
    {
        byte[] full = File.ReadAllBytes(TestDataPath.Get("v2-bzip2.mpq"));
        Assert.AreEqual(0x2Cu, BinaryPrimitives.ReadUInt32LittleEndian(full.AsSpan(0x04)));
        uint blockPos = BinaryPrimitives.ReadUInt32LittleEndian(full.AsSpan(0x14));
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(full.AsSpan(0x1C));
        Assert.AreEqual((long)full.Length, (long)blockPos + blocks * 16, "the block table is the end of the fixture");
        byte[] data = full[..^8];
        // Keep the archive size consistent, so the stored block table size is still the full table (not "compressed").
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x08), (uint)full.Length);

        var lastBlockFile = FilesByBlock(full).Single(f => f.Block == blocks - 1).Name;
        var expected = ExpectedArchive.Load("v2-bzip2.mpq");
        using (var mpq = MpqArchive.Open(new MemoryStream(data), MpqOpenMode.ReadWrite))
        {
            Assert.IsFalse(mpq.Contains(lastBlockFile));
            foreach (var file in expected.Files.Where(f => !f.Internal && f.Name != lastBlockFile))
                Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, file.Name))), file.Name);
            Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("new.txt", new MemoryStream([1])));
        }
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(data), options: Strict));
    }

    /// <summary>StormLib IsValidHashEntry1: a block whose data starts outside the file is not a file.</summary>
    [TestMethod]
    public void BlockOutsideTheFile_IsIgnored()
    {
        byte[] data = Load();
        var (name, block) = FilesByBlock(data).First(f => !ListFile.IsInternalName(f.Name));
        RewriteBlock(data, block, entry => BinaryPrimitives.WriteUInt32LittleEndian(entry, (uint)data.Length + 0x100));

        using var mpq = MpqArchive.Open(new MemoryStream(data));
        Assert.IsFalse(mpq.Contains(name));
        foreach (var file in ExpectedArchive.Load(Archive).Files.Where(f => !f.Internal && f.Name != name))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, file.Name))), file.Name);
    }

    /// <summary>In malformed archives, files of 2 GB or more are not accepted (IsValidHashEntry1).</summary>
    [TestMethod]
    public void HugeFileInMalformedArchive_IsIgnored()
    {
        byte[] data = Load();
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x04), 0x40);
        var (name, block) = FilesByBlock(data).First(f => !ListFile.IsInternalName(f.Name));
        RewriteBlock(data, block, entry => BinaryPrimitives.WriteUInt32LittleEndian(entry[8..], 0x80000000));

        using var mpq = MpqArchive.Open(new MemoryStream(data));
        Assert.IsFalse(mpq.Contains(name));
    }

    [TestMethod]
    public void UnknownFormatVersion_IsMalformedV1()
    {
        byte[] data = Load();
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x0C), 7);
        AssertRepaired(data, mpq => Assert.AreEqual(MpqFormatVersion.Version1, mpq.Header.FormatVersion));
    }

    /// <summary>Repaired archives read the valid files, cannot be modified, and are rejected in strict mode.</summary>
    private static void AssertRepaired(byte[] data, Action<MpqArchive> check, bool checkFiles = true)
    {
        using (var mpq = MpqArchive.Open(new MemoryStream(data), MpqOpenMode.ReadWrite))
        {
            check(mpq);
            if (checkFiles)
                AssertFilesRead(mpq);
            Assert.ThrowsExactly<InvalidOperationException>(() => mpq.AddFile("new.txt", new MemoryStream([1])));
            Assert.ThrowsExactly<InvalidOperationException>(() => mpq.SignWeak());
        }
        Assert.ThrowsExactly<InvalidDataException>(() => MpqArchive.Open(new MemoryStream(data), options: Strict));
    }

    private static void AssertFilesRead(MpqArchive mpq)
    {
        foreach (var file in ExpectedArchive.Load(Archive).Files.Where(f => !f.Internal))
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, file.Name))), file.Name);
    }

    private static byte[] Load()
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get(Archive));
        Assert.AreEqual(MpqHeaderReader.HeaderSignature, BinaryPrimitives.ReadUInt32LittleEndian(data), "the fixture starts with its header");
        return data;
    }

    /// <summary>Block index of every named file in an undamaged archive.</summary>
    private static List<(string Name, uint Block)> FilesByBlock(byte[] data)
    {
        using var mpq = MpqArchive.Open(new MemoryStream(data));
        return mpq.Entries.Where(e => e.Name is not null).Select(e => (e.Name!, (uint)e.BlockIndex)).ToList();
    }

    private static void RewriteBlock(byte[] data, uint block, Action<Span<byte>> change)
    {
        uint blockPos = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x14));
        uint blocks = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x1C));
        var table = data.AsSpan((int)blockPos, (int)blocks * 16);
        StormCrypto.DecryptBlock(table, StormCrypto.BlockTableKey);
        change(table.Slice((int)block * 16, 16));
        StormCrypto.EncryptBlock(table, StormCrypto.BlockTableKey);
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
