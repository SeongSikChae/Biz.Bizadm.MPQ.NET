using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class MpqFileTableTests
{
    // patch-1.mpq is excluded: its expected file describes the patch chain, not the archive itself.
    public static IEnumerable<object[]> Archives =>
    [
        ["v1-zlib.mpq"], ["v1-pkware.mpq"], ["v1-encrypted.mpq"], ["v1-sector-options.mpq"], ["v1-legacy-masks.mpq"],
        ["v1-weak-signed.mpq"], ["v2-bzip2.mpq"], ["v2-single-unit.mpq"], ["sc2-userdata.SC2Replay"], ["patch-base.mpq"],
        ["v3-lzma.mpq"], ["v4-mixed.mpq"],
    ];

    [TestMethod]
    [DynamicData(nameof(Archives))]
    public void Find_ReturnsEveryFileWithStormLibSizesAndFlags(string archive)
    {
        var expected = ExpectedArchive.Load(archive);
        var table = Load(archive);

        foreach (var file in expected.Files)
        {
            var entry = table.Find(file.Name);
            Assert.IsNotNull(entry, file.Name);
            Assert.AreEqual((uint)file.Size, entry.FileSize, file.Name);
            Assert.AreEqual(file.CompressedSize, entry.CompressedSize, file.Name);
            Assert.AreEqual(file.Flags, (uint)entry.Flags, file.Name);
            Assert.IsTrue(entry.Flags.HasFlag(MpqFileFlags.Exists), file.Name);
        }
        Assert.IsNull(table.Find("does-not-exist.txt"));
    }

    [TestMethod]
    public void Find_IgnoresAsciiCase()
    {
        var table = Load("v1-zlib.mpq");
        Assert.AreSame(table.Find("readme.txt"), table.Find("README.TXT"));
        Assert.AreSame(table.Find(@"data\random.bin"), table.Find(@"DATA\Random.Bin"));
    }

    [TestMethod]
    public void Find_AcceptsSlashForBackslashName()
    {
        var table = Load("v1-zlib.mpq");
        var entry = table.Find(@"data\random.bin");

        Assert.IsNotNull(entry);
        Assert.AreSame(entry, table.Find("data/random.bin"));
    }

    /// <summary>text/slash.txt was stored with '/' by StormLib; it is found with either separator.</summary>
    [TestMethod]
    public void Find_AcceptsBackslashForSlashName()
    {
        var table = Load("v1-zlib.mpq");
        uint backslashA = StormCrypto.HashStringSlash(@"text\slash.txt", MpqHashType.NameA);
        Assert.IsFalse(table.HashEntries.Any(h => h.HashA == backslashA), "The name should be stored with '/'.");

        var entry = table.Find("text/slash.txt");
        Assert.IsNotNull(entry);
        Assert.AreSame(entry, table.Find(@"text\slash.txt"));
    }

    [TestMethod]
    public void Find_PrefersExactLocaleThenNeutral()
    {
        const string name = @"ui\text.txt";
        const ushort korean = 0x0412;
        var neutral = new MpqFileEntry { FileSize = 1 };
        var localized = new MpqFileEntry { FileSize = 2 };

        var hash = Enumerable.Repeat(new MpqHashEntry(0, 0, 0, 0, 0, MpqHashEntry.Free), 8).ToArray();
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & 7;
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);
        hash[start] = new MpqHashEntry(a, b, korean, 0, 0, 1);
        hash[(start + 1) & 7] = new MpqHashEntry(a, b, 0, 0, 0, 0);

        var table = new MpqFileTable(hash, [neutral, localized]);

        Assert.AreSame(localized, table.Find(name, korean));
        Assert.AreSame(neutral, table.Find(name));
        Assert.AreSame(neutral, table.Find(name, 0x0409));
    }

    [TestMethod]
    public void Find_SkipsDeletedSlotsAndStopsAtFreeSlot()
    {
        const string name = "deleted.txt";
        var entry = new MpqFileEntry { FileSize = 7 };
        uint start = StormCrypto.HashStringSlash(name, MpqHashType.TableOffset) & 3;
        uint a = StormCrypto.HashStringSlash(name, MpqHashType.NameA);
        uint b = StormCrypto.HashStringSlash(name, MpqHashType.NameB);

        var hash = Enumerable.Repeat(new MpqHashEntry(0, 0, 0, 0, 0, MpqHashEntry.Free), 4).ToArray();
        hash[start] = new MpqHashEntry(a, b, 0, 0, 0, MpqHashEntry.Deleted);
        hash[(start + 1) & 3] = new MpqHashEntry(a, b, 0, 0, 0, 0);
        Assert.AreSame(entry, new MpqFileTable(hash, [entry]).Find(name));

        hash[start] = new MpqHashEntry(0, 0, 0, 0, 0, MpqHashEntry.Free);
        Assert.IsNull(new MpqFileTable(hash, [entry]).Find(name));
    }

    [TestMethod]
    public void Load_CopiesHashFieldsToEntries()
    {
        var table = Load("v1-zlib.mpq");
        var entry = table.Find("readme.txt");

        Assert.IsNotNull(entry);
        Assert.AreEqual(StormCrypto.HashStringSlash("readme.txt", MpqHashType.NameA), entry.HashA);
        Assert.AreEqual(StormCrypto.HashStringSlash("readme.txt", MpqHashType.NameB), entry.HashB);
        Assert.AreEqual((ushort)0, entry.Locale);
    }

    private static MpqFileTable Load(string archive)
    {
        using var stream = File.OpenRead(TestDataPath.Get(archive));
        var (header, _, headerOffset) = MpqHeaderReader.Find(stream);
        return MpqFileTable.Load(stream, header, headerOffset);
    }
}
