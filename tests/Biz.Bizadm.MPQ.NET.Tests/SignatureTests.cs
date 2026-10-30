using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET.Tests;

[TestClass]
public sealed class SignatureTests
{
    private string _directory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _directory = Path.Combine(Path.GetTempPath(), "mpq-signature-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    [TestCleanup]
    public void Cleanup() => Directory.Delete(_directory, recursive: true);

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 400).Select(i => $"Line {i:D4}: the quick brown fox\r\n")));

    [TestMethod]
    public void WeakSignature_StormLibFixtureIsValid()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-weak-signed.mpq"));
        Assert.AreEqual(MpqSignatureStatus.WeakValid, mpq.VerifySignature());
    }

    [TestMethod]
    public void WeakSignature_UnsignedArchiveHasNone()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        Assert.AreEqual(MpqSignatureStatus.None, mpq.VerifySignature());
    }

    /// <summary>Changing one byte of the archive data or of the signature makes the weak signature invalid.</summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void WeakSignature_ChangedByteIsInvalid(bool inSignature)
    {
        byte[] archive = File.ReadAllBytes(TestDataPath.Get("v1-weak-signed.mpq"));
        long signature = SignaturePosition(archive);
        long target = inSignature ? signature + 20 : 0x40;
        Assert.IsTrue(inSignature || target < signature || target >= signature + MpqSignature.FileSize);
        archive[target] ^= 0x01;

        using var mpq = MpqArchive.Open(new MemoryStream(archive));
        Assert.AreEqual(MpqSignatureStatus.WeakInvalid, mpq.VerifySignature());
    }

    /// <summary>PKCS#1 v1.5 signing is deterministic, so signing the fixture's MD5 gives StormLib's bytes.</summary>
    [TestMethod]
    public void SignWeak_ReproducesStormLibSignature()
    {
        byte[] archive = File.ReadAllBytes(TestDataPath.Get("v1-weak-signed.mpq"));
        int signature = (int)SignaturePosition(archive);
        byte[] stored = archive.AsSpan(signature, MpqSignature.FileSize).ToArray();
        Assert.IsTrue(MpqSignature.IsWeakSigned(stored));

        archive.AsSpan(signature, MpqSignature.FileSize).Clear();
        using var stream = new MemoryStream(archive);
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        byte[] md5 = MD5.HashData(archive.AsSpan((int)offset, (int)header.ArchiveSize));

        CollectionAssert.AreEqual(stored, MpqSignature.SignWeak(md5, MpqSignature.WeakPrivateKey));
    }

    [TestMethod]
    [DataRow(MpqFormatVersion.Version1)]
    [DataRow(MpqFormatVersion.Version2)]
    [DataRow(MpqFormatVersion.Version3)]
    [DataRow(MpqFormatVersion.Version4)]
    public void SignWeak_StormLibAcceptsTheSignature(MpqFormatVersion version)
    {
        string path = Path.Combine(_directory, $"signed-{version}.mpq");
        using (var mpq = MpqArchive.Create(path, new MpqArchiveCreateOptions { FormatVersion = version }))
        {
            mpq.AddFile("readme.txt", new MemoryStream(Text));
            mpq.SignWeak();
        }

        AssertWeakSigned(path);
        StormLibVerifier.AssertStormLibReads(path, version, 4096, new Dictionary<string, byte[]> { ["readme.txt"] = Text },
            weakSignature: true);
    }

    /// <summary>StormLib re-signs a weak-signed archive after every change; so does this library.</summary>
    [TestMethod]
    public void ModifiedWeakSignedArchiveIsSignedAgain()
    {
        var expected = ExpectedArchive.Load("v1-weak-signed.mpq");
        string path = Path.Combine(_directory, "modified.mpq");
        File.Copy(TestDataPath.Get("v1-weak-signed.mpq"), path);
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.AddFile("new.txt", new MemoryStream(Text));
            // Pending changes are flushed before verifying.
            Assert.AreEqual(MpqSignatureStatus.WeakValid, mpq.VerifySignature());
        }

        AssertWeakSigned(path);
        var files = new Dictionary<string, byte[]> { ["new.txt"] = Text };
        using (var mpq = MpqArchive.Open(path))
        {
            foreach (var file in expected.Files.Where(f => !f.Internal))
                files[file.Name] = ReadAll(mpq, file.Name);
        }
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, expected.SectorSize, files, weakSignature: true);
    }

    /// <summary>StormLib signs again when it saves the tables of a compacted archive.</summary>
    [TestMethod]
    public void Compact_SignsAgain()
    {
        string path = Path.Combine(_directory, "compact.mpq");
        using (var mpq = MpqArchive.Create(path))
        {
            mpq.AddFile("deleted.txt", new MemoryStream(Text));
            mpq.AddFile("readme.txt", new MemoryStream(Text));
            mpq.SignWeak();
        }
        using (var mpq = MpqArchive.Open(path, MpqOpenMode.ReadWrite))
        {
            mpq.DeleteFile("deleted.txt");
            mpq.Compact();
        }

        AssertWeakSigned(path);
        StormLibVerifier.AssertStormLibReads(path, MpqFormatVersion.Version1, 4096, new Dictionary<string, byte[]> { ["readme.txt"] = Text },
            weakSignature: true);
    }

    /// <summary>
    /// Like libtomcrypt in StormLib, the weak check accepts a 0xFF padding shorter than 8 bytes and data after the
    /// DigestInfo, and rejects a wrong digest or a missing separator.
    /// </summary>
    [TestMethod]
    public void VerifyWeak_DecodesLikeLibTomCrypt()
    {
        byte[] md5 = MD5.HashData("data"u8);
        byte[] digestInfo = [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10, .. md5];
        byte[] Sign(byte[] encoded)
        {
            var key = MpqSignature.WeakPrivateKey;
            var signature = BigInteger.ModPow(new BigInteger(encoded, isUnsigned: true, isBigEndian: true), key.PrivateExponent!.Value, key.Modulus);
            var file = new byte[MpqSignature.FileSize];
            MpqSignature.WriteLittleEndian(signature, file.AsSpan(8, MpqSignature.WeakSize));
            return file;
        }

        byte[] shortPadding = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, .. digestInfo, .. new byte[64 - 7 - digestInfo.Length]];
        Assert.IsTrue(MpqSignature.VerifyWeak(Sign(shortPadding), md5, MpqSignature.WeakPublicKey));
        Assert.IsTrue(MpqSignature.VerifyWeak(MpqSignature.SignWeak(md5, MpqSignature.WeakPrivateKey), md5, MpqSignature.WeakPublicKey));
        Assert.IsFalse(MpqSignature.VerifyWeak(MpqSignature.SignWeak(md5, MpqSignature.WeakPrivateKey), MD5.HashData("other"u8), MpqSignature.WeakPublicKey));

        byte[] noSeparator = [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, 62)];
        Assert.IsFalse(MpqSignature.VerifyWeak(Sign(noSeparator), md5, MpqSignature.WeakPublicKey));
    }

    [TestMethod]
    public void SignWeak_RequiresWritableArchive()
    {
        using var mpq = MpqArchive.Open(TestDataPath.Get("v1-zlib.mpq"));
        Assert.ThrowsExactly<InvalidOperationException>(mpq.SignWeak);
    }

    /// <summary>
    /// Strong signatures are checked with a test key (the Blizzard private keys are unknown): "NGIS" and the
    /// signature of 0x0B, 0xBB padding and the reversed SHA-1, with the tail the key uses.
    /// </summary>
    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    public void StrongSignature_TestKey(int tailIndex)
    {
        var tail = (StrongSignatureTail)tailIndex;
        string path = Path.Combine(_directory, "Strong.Map.mpq");
        using (var mpq = MpqArchive.Create(path))
            mpq.AddFile("readme.txt", new MemoryStream(Text));

        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: true);
        var key = new RsaKey(new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true),
            new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true),
            new BigInteger(parameters.D, isUnsigned: true, isBigEndian: true));
        byte[] archive = File.ReadAllBytes(path);
        byte[] tailBytes = tail switch
        {
            StrongSignatureTail.FileName => Encoding.ASCII.GetBytes("STRONG.MAP.MPQ"),
            StrongSignatureTail.Archive => "ARCHIVE"u8.ToArray(),
            _ => [],
        };
        byte[] sha1 = SHA1.HashData([.. archive, .. tailBytes]);
        var padded = new BigInteger(MpqSignature.StrongPadding(sha1), isUnsigned: true, isBigEndian: true);
        var signature = new byte[4 + MpqSignature.StrongSize];
        "NGIS"u8.CopyTo(signature);
        MpqSignature.WriteLittleEndian(BigInteger.ModPow(padded, key.PrivateExponent!.Value, key.Modulus), signature.AsSpan(4));
        File.WriteAllBytes(path, [.. archive, .. signature]);

        using (var mpq = MpqArchive.Open(path))
        {
            Assert.AreEqual(MpqSignatureStatus.StrongValid, mpq.VerifySignature([(key, tail)]));
            Assert.AreEqual(MpqSignatureStatus.StrongInvalid, mpq.VerifySignature());
            var otherTail = (StrongSignatureTail)(((int)tail + 1) % 3);
            Assert.AreEqual(MpqSignatureStatus.StrongInvalid, mpq.VerifySignature([(key, otherTail)]));
        }

        byte[] changed = File.ReadAllBytes(path);
        changed[0x40] ^= 0x01;
        File.WriteAllBytes(path, changed);
        using (var mpq = MpqArchive.Open(path))
            Assert.AreEqual(MpqSignatureStatus.StrongInvalid, mpq.VerifySignature([(key, tail)]));
    }

    /// <summary>Data after the archive that does not start with "NGIS" is not a signature.</summary>
    [TestMethod]
    public void StrongSignature_OtherTrailingDataIsNone()
    {
        using var stream = new MemoryStream();
        using (var mpq = MpqArchive.Create(stream, leaveOpen: true))
            mpq.AddFile("readme.txt", new MemoryStream(Text));
        stream.Position = stream.Length;
        stream.Write(new byte[300]);

        using var reopened = MpqArchive.Open(stream);
        Assert.AreEqual(MpqSignatureStatus.None, reopened.VerifySignature());
    }

    private static void AssertWeakSigned(string path)
    {
        byte[] archive = File.ReadAllBytes(path);
        Assert.IsTrue(MpqSignature.IsWeakSigned(archive.AsSpan((int)SignaturePosition(archive), MpqSignature.FileSize)),
            "the (signature) file is still zero");
        using var mpq = MpqArchive.Open(path);
        Assert.AreEqual(MpqSignatureStatus.WeakValid, mpq.VerifySignature());
    }

    private static long SignaturePosition(byte[] archive)
    {
        using var stream = new MemoryStream(archive);
        var (header, _, offset) = MpqHeaderReader.Find(stream);
        var table = MpqFileTable.Load(stream, header, offset);
        return offset + table.Find(ListFile.SignatureName)!.FilePosition;
    }

    private static byte[] ReadAll(MpqArchive mpq, string name)
    {
        using var stream = mpq.OpenFile(name);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
