using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;
using Biz.Bizadm.MPQ.NET.Internal.Patch;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class PatchTests
{
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-patch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Version1 = "version 1"u8.ToArray();
    private static readonly byte[] Version2 = "version 2 of the file"u8.ToArray();

    /// <summary>The StormLib-generated chain (BSD0 patch with RLE) reads like StormLib reads it.</summary>
    [TestMethod]
    public void StormLibChain_MatchesExpected()
    {
        var expected = ExpectedArchive.Load("patch-1.mpq");
        using var mpq = MpqArchive.Open(TestDataPath.Get(expected.BaseArchive!));
        foreach (string patch in expected.PatchArchives)
            mpq.OpenPatchArchive(TestDataPath.Get(patch));

        foreach (var file in expected.Files)
        {
            Assert.IsTrue(mpq.Contains(file.Name), file.Name);
            Assert.AreEqual(file.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, file.Name))), file.Name);
        }
    }

    [TestMethod]
    public void WithoutChain_BaseVersionAndNoPatchFiles()
    {
        var baseExpected = ExpectedArchive.Load("patch-base.mpq");
        var patched = baseExpected.Files.Single(f => f.Name == @"data\patched.txt");
        using (var mpq = MpqArchive.Open(TestDataPath.Get("patch-base.mpq")))
            Assert.AreEqual(patched.Sha256, Convert.ToHexString(SHA256.HashData(ReadAll(mpq, patched.Name))));

        // Patch files are only readable through a chain (StormLib behavior).
        using var patch = MpqArchive.Open(TestDataPath.Get("patch-1.mpq"));
        Assert.IsFalse(patch.Contains(patched.Name));
        Assert.ThrowsExactly<FileNotFoundException>(() => patch.OpenFile(patched.Name));
    }

    [TestMethod]
    public void OpenPatchArchive_RequiresReadOnlyBase()
    {
        string path = Path.Combine(_directory, "base.mpq");
        File.Copy(TestDataPath.Get("patch-base.mpq"), path);
        using var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite);
        Assert.ThrowsExactly<InvalidOperationException>(() => mpq.OpenPatchArchive(TestDataPath.Get("patch-1.mpq")));
    }

    /// <summary>A changed md5_after_patch makes the patched file corrupt.</summary>
    [TestMethod]
    public void Bsd0_Md5MismatchThrows()
    {
        var (baseData, baseMd5) = ReadFixtureFile("patch-base.mpq", @"data\patched.txt");
        var (patchFile, _) = ReadFixtureFile("patch-1.mpq", @"data\patched.txt");
        var expected = ExpectedArchive.Load("patch-1.mpq").Files.Single(f => f.Name == @"data\patched.txt");
        Assert.AreEqual(expected.Sha256, Convert.ToHexString(SHA256.HashData(MpqPatch.ApplyChain(baseData, baseMd5, [patchFile], 0x100))));

        patchFile[0x28] ^= 0x01;
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(baseData, baseMd5, [patchFile], 0x100));
    }

    /// <summary>COPY: the data after the header is the new file.</summary>
    [TestMethod]
    public void Copy_ReplacesTheFile()
    {
        byte[] patch = CreateCopyPatch(Version1, Version2);
        CollectionAssert.AreEqual(Version2, MpqPatch.ApplyChain(Version1, MD5.HashData(Version1), [patch], 0x100));

        byte[] wrongMd5 = CreateCopyPatch(Version1, Version2);
        wrongMd5[0x28] ^= 0x01;
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(Version1, null, [wrongMd5], 0x100));

        byte[] wrongSignature = CreateCopyPatch(Version1, Version2);
        wrongSignature[0] = 0;
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(Version1, null, [wrongSignature], 0x100));
    }

    /// <summary>
    /// StormLib Patch_Process: a patch is skipped when the next one also patches the current version, so a corrupt
    /// patch that is superseded is never applied.
    /// </summary>
    [TestMethod]
    public void Chain_SkipsPatchSupersededByTheNext()
    {
        byte[] corrupt = CreateCopyPatch(Version1, Version2);
        corrupt[0x28] ^= 0x01;
        byte[] version3 = "third"u8.ToArray();
        byte[] next = CreateCopyPatch(Version1, version3);
        CollectionAssert.AreEqual(version3, MpqPatch.ApplyChain(Version1, MD5.HashData(Version1), [corrupt, next], 0x100));

        // Without the base MD5 nothing matches, so both patches are applied and the corrupt one fails.
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(Version1, null, [corrupt, next], 0x100));
    }

    /// <summary>Corrupt sizes and offsets are reported as InvalidDataException, not as other exceptions.</summary>
    [TestMethod]
    public void CorruptPatches_ThrowInvalidData()
    {
        byte[] huge = CreateCopyPatch(Version1, Version2);
        BinaryPrimitives.WriteUInt32LittleEndian(huge.AsSpan(0x04), 0x90000000);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(Version1, null, [huge], 0x100));

        // A negative old move wraps the old offset below zero; the next control entry would read outside the old data.
        var bsdiff = new byte[0x20 + 24 + 0x20];
        "BSDIFF40"u8.CopyTo(bsdiff);
        BinaryPrimitives.WriteUInt64LittleEndian(bsdiff.AsSpan(0x08), 24);
        BinaryPrimitives.WriteUInt64LittleEndian(bsdiff.AsSpan(0x10), 0x20);
        BinaryPrimitives.WriteUInt64LittleEndian(bsdiff.AsSpan(0x18), 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(bsdiff.AsSpan(0x28), 0x80000010); // add 0, move 0, old move -0x10
        BinaryPrimitives.WriteUInt32LittleEndian(bsdiff.AsSpan(0x2C), 0x20);       // add 0x20
        byte[] patch = new byte[MpqPatch.HeaderSize + bsdiff.Length];
        CreateCopyPatch(new byte[0x40], new byte[0x20]).AsSpan(0, MpqPatch.HeaderSize).CopyTo(patch);
        BinaryPrimitives.WriteUInt32LittleEndian(patch.AsSpan(0x04), (uint)patch.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(patch.AsSpan(0x3C), (uint)(0x0C + bsdiff.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(patch.AsSpan(0x40), 0x30445342); // BSD0
        patch.AsSpan(0x28, 16).Clear(); // no md5_after_patch
        bsdiff.CopyTo(patch, MpqPatch.HeaderSize);
        Assert.ThrowsExactly<InvalidDataException>(() => MpqPatch.ApplyChain(new byte[0x40], null, [patch], 0x100));
    }

    [TestMethod]
    public void Rle_DecodesLiteralsAndZeroRuns()
    {
        var output = new byte[8];
        MpqPatch.DecompressRle(output, [0xAA, 0xAA, 0xAA, 0xAA, 0x81, 1, 2, 0x02, 0x80, 3]);
        CollectionAssert.AreEqual(new byte[] { 1, 2, 0, 0, 0, 3, 0, 0 }, output);
    }

    /// <summary>A file in a patch archive that is not a patch file replaces the base version; the prefix is given.</summary>
    [TestMethod]
    public void ExplicitPrefix_PlainFilesReplaceTheBase()
    {
        string basePath = CreateArchive("base.mpq", ("a.txt", Version1), ("b.txt", Version1));
        string patchPath = CreateArchive("patch.mpq", (@"pre\a.txt", Version2), (@"pre\new.txt", Version2));

        using var mpq = MpqArchive.Open(basePath);
        mpq.OpenPatchArchive(patchPath, "pre");
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "a.txt"));
        CollectionAssert.AreEqual(Version1, ReadAll(mpq, "b.txt"));
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "new.txt"));
        Assert.IsFalse(mpq.Contains("missing.txt"));
        Assert.AreEqual(1, mpq.PatchArchives.Count);
    }

    [TestMethod]
    public void NoPrefix_WhenNothingIsDetected()
    {
        string basePath = CreateArchive("base.mpq", ("a.txt", Version1));
        string patchPath = CreateArchive("patch.mpq", ("a.txt", Version2), (@"pre\a.txt", Version1));

        using var mpq = MpqArchive.Open(basePath);
        mpq.OpenPatchArchive(patchPath);
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "a.txt"));
    }

    /// <summary>StormLib FindPatchPrefix_WoW_13164_13623: "Base\" or the language of the base locale archive.</summary>
    [TestMethod]
    [DataRow(null, "Base")]
    [DataRow("locale-enGB-md5.lst", "enGB")]
    [DataRow("expansion1-speech-deDE-md5.lst", "deDE")]
    public void WowPrefix_FromBaseLanguage(string? languageFile, string prefix)
    {
        var baseFiles = new List<(string, byte[])> { ("a.txt", Version1) };
        if (languageFile is not null)
            baseFiles.Add((languageFile, Version1));
        string basePath = CreateArchive("base.mpq", [.. baseFiles]);
        string patchPath = CreateArchive("patch.mpq", (@"base\(patch_metadata)", Version1), (prefix + @"\a.txt", Version2));

        using var mpq = MpqArchive.Open(basePath);
        mpq.OpenPatchArchive(patchPath);
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "a.txt"));
        // StormLib GetPatchFileName drops "OldWorld\" before adding the prefix.
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, @"OldWorld\a.txt"));
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "OldWorld/a.txt"));
    }

    /// <summary>StormLib FindPatchPrefix_SC2_ArchiveName: the base path from "Mods" (or Campaigns, Battle.net).</summary>
    [TestMethod]
    public void Sc2Prefix_FromArchivePath()
    {
        string folder = Path.Combine(_directory, "Mods", "Test.SC2Mod");
        Directory.CreateDirectory(folder);
        string basePath = CreateArchive(Path.Combine(folder, "Base.SC2Data"), ("StreamingBuckets.txt", Version1), ("a.txt", Version1));
        string prefix = @"Mods\Test.SC2Mod\Base.SC2Data\";
        string patchPath = CreateArchive("patch.mpq", (prefix + "(patch_metadata)", Version1), (prefix + "a.txt", Version2));

        using var mpq = MpqArchive.Open(basePath);
        mpq.OpenPatchArchive(patchPath);
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "a.txt"));
    }

    /// <summary>StormLib FindPatchPrefix_SC2_HelperFile: "PatchPrefix=..." in "&lt;archive&gt;-PATCH".</summary>
    [TestMethod]
    public void Sc2Prefix_FromHelperFile()
    {
        string basePath = CreateArchive("x.SC2Data", ("StreamingBuckets.txt", Version1), ("a.txt", Version1));
        File.WriteAllText(basePath + "-PATCH", "PatchPrefix = Foo\\Bar\r\n");
        string patchPath = CreateArchive("patch.mpq", (@"Foo\Bar\(patch_metadata)", Version1), (@"Foo\Bar\a.txt", Version2));

        using var mpq = MpqArchive.Open(basePath);
        mpq.OpenPatchArchive(patchPath);
        CollectionAssert.AreEqual(Version2, ReadAll(mpq, "a.txt"));
    }

    [TestMethod]
    public void Sc2Prefix_NotFoundFails()
    {
        string basePath = CreateArchive("x.SC2Data", ("StreamingBuckets.txt", Version1));
        string patchPath = CreateArchive("patch.mpq", ("a.txt", Version2));

        using var mpq = MpqArchive.Open(basePath);
        Assert.ThrowsExactly<InvalidOperationException>(() => mpq.OpenPatchArchive(patchPath));
        Assert.AreEqual(0, mpq.PatchArchives.Count);
        // The patch archive was closed again, so it can be deleted.
        File.Delete(patchPath);
    }

    private string CreateArchive(string name, params (string Name, byte[] Data)[] files)
    {
        string path = Path.IsPathRooted(name) ? name : Path.Combine(_directory, name);
        using var mpq = MpqArchive.Create(path);
        foreach (var (fileName, data) in files)
            mpq.AddFile(fileName, new MemoryStream(data));
        return path;
    }

    private static byte[] CreateCopyPatch(byte[] before, byte[] after)
    {
        var patch = new byte[MpqPatch.HeaderSize + after.Length];
        var span = patch.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, 0x48435450); // PTCH
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x04..], (uint)patch.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], (uint)before.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], (uint)after.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x10..], 0x5F35444D); // MD5_
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x14..], 0x28);
        MD5.HashData(before).CopyTo(span[0x18..]);
        MD5.HashData(after).CopyTo(span[0x28..]);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x38..], 0x4D524658); // XFRM
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x3C..], (uint)(0x0C + after.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x40..], 0x59504F43); // COPY
        after.CopyTo(span[MpqPatch.HeaderSize..]);
        return patch;
    }

    /// <summary>The data of a fixture file (for patch files, the patch data) and its MD5 from (attributes).</summary>
    private static (byte[] Data, byte[]? Md5) ReadFixtureFile(string archive, string name)
    {
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        var entry = table.Find(name)!;
        using (var mpq = MpqArchive.Open(TestDataPath.Get(archive)))
            MpqAttributes.Apply(ReadAll(mpq, ListFile.AttributesName), (int)header.BlockTableSize, table.Entries);
        var reader = new MpqSectorReader(stream, offset, entry, header.FormatVersion, header.SectorSize, fileKey: 0);
        return (reader.ReadAll(), entry.Md5);
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
