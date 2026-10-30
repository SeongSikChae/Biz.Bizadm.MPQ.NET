using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>
/// v2 hi-block table. StormLib writes none for archives under 4 GB, so the tests append one to a copy of a
/// v2 fixture and point HiBlockTablePos64 (header offset 0x20) at it.
/// </summary>
[TestClass]
public sealed class MpqHiBlockTests
{
    [TestMethod]
    [DataRow("v2-bzip2.mpq")]
    [DataRow("sc2-userdata.SC2Replay")]
    public void ZeroHiBlockTable_KeepsPositionsAndContent(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        using var mpq = MpqArchive.Open(WithHiBlockTable(archive, _ => 0));

        Assert.AreNotEqual(0, mpq.Header.HiBlockTablePosition);
        foreach (var file in expected.Files)
        {
            using var stream = mpq.OpenFile(file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(stream)), file.Name);
        }
    }

    [TestMethod]
    public void HiBlockTable_AddsHighBitsToFilePosition()
    {
        var plain = LoadTable(new MemoryStream(File.ReadAllBytes(TestDataPath.Get("v2-bzip2.mpq"))));
        var patched = LoadTable(WithHiBlockTable("v2-bzip2.mpq", index => (ushort)(index + 1)));

        Assert.AreEqual(plain.Entries.Count, patched.Entries.Count);
        for (int i = 0; i < plain.Entries.Count; i++)
            Assert.AreEqual(plain.Entries[i].FilePosition | ((long)(i + 1) << 32), patched.Entries[i].FilePosition);
    }

    private static MpqFileTable LoadTable(Stream stream)
    {
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        return MpqFileTable.Load(stream, header, headerOffset);
    }

    private static MemoryStream WithHiBlockTable(string archive, Func<int, ushort> hiForBlock)
    {
        byte[] data = File.ReadAllBytes(TestDataPath.Get(archive));
        using var probe = new MemoryStream(data);
        var (header, _, headerOffset) = MpqHeaderReader.Find(probe);
        Assert.AreEqual(MpqFormatVersion.Version2, header.FormatVersion);
        Assert.AreEqual(0, header.HiBlockTablePosition, "fixture already has a hi-block table");

        var hi = new byte[header.BlockTableSize * 2];
        for (int i = 0; i < header.BlockTableSize; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(hi.AsSpan(i * 2), hiForBlock(i));

        byte[] result = [.. data, .. hi];
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan((int)headerOffset + 0x20), (ulong)(data.Length - headerOffset));
        return new MemoryStream(result, writable: false);
    }
}
