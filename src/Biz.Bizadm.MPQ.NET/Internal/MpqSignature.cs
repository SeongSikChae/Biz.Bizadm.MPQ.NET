using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>Plain RSA key; the private exponent is only known for the public weak signing key.</summary>
internal sealed record RsaKey(BigInteger Modulus, BigInteger Exponent, BigInteger? PrivateExponent = null)
{
    public int Size => (int)((Modulus.GetBitLength() + 7) / 8);
}

/// <summary>Data appended to the SHA-1 of the archive before checking a strong signature (StormLib CalculateMpqHashSha1).</summary>
internal enum StrongSignatureTail
{
    None,
    FileName,
    Archive,
}

/// <summary>
/// Weak and strong MPQ signatures (StormLib SFileVerify.cpp). RSA is computed with <see cref="BigInteger"/>, because the
/// weak signature uses a 512-bit key and MD5, which platform providers may refuse.
/// </summary>
internal static class MpqSignature
{
    public const int WeakSize = 64;
    public const int FileSize = WeakSize + 8;
    public const int StrongSize = 256;
    public const uint StrongId = 0x5349474E; // "NGIS"

    // Keys from StormLib SFileVerify.cpp (created by Jean-Francois Roy). The weak private key is public knowledge.
    public static readonly RsaKey WeakPrivateKey = ParsePrivateKey(
        "MIIBOQIBAAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe2kfdfEk3G/j66w4KkhZ1" +
        "V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQJANtiztVDMJh2hE1hjPDKy" +
        "UmEJ9U/aN3gomuKOjbQbQ/bWWcM/WfhSVHmPqtqh/bQI2UXFr0rnXngeteZHLr/b" +
        "8QIhAMuWriSKGMACw18/rVVfUrThs915odKBH1Alr3vMVVzZAiEAuBHPSQkgwcb6" +
        "L4MWaiKuOzq08mSyNqPeN8oSy18q848CIHeMn+3s+eOmu7su1UYQl6yH7OrdBd1q" +
        "3UxfFNEJiAbhAiAqxdCyOxHGlbM7aS3DOg3cq5ayoN2cvtV7h1R4t8OmVwIgF+5z" +
        "/6vkzBUsZhd8Nwyis+MeQYH0rpFpMKdTlqmPF2Q=");

    public static readonly RsaKey WeakPublicKey = ParsePublicKey(
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe" +
        "2kfdfEk3G/j66w4KkhZ1V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQ==");

    /// <summary>StormLib VerifyStrongSignature: the keys in the order they are tried, with the SHA-1 tail each uses.</summary>
    public static readonly IReadOnlyList<(RsaKey Key, StrongSignatureTail Tail)> StrongKeys =
    [
        // Blizzard
        (ParsePublicKey(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsQZ+ziT2h8h+J/iMQpgd" +
            "tH1HaJzOBE3agjU4yMPcrixaPOZoA4t8bwfey7qczfWywocYo3pleytFF+IuD4HD" +
            "Fl9OXN1SFyupSgMx1EGZlgbFAomnbq9MQJyMqQtMhRAjFgg4TndS7YNb+JMSAEKp" +
            "kXNqY28n/EVBHD5TsMuVCL579gIenbr61dI92DDEdy790IzIG0VKWLh/KOTcTJfm" +
            "Ds/7HQTkGouVW+WUsfekuqNQo7ND9DBnhLjLjptxeFE2AZqYcA1ao3S9LN3GL1tW" +
            "lVXFIX9c7fWqaVTQlZ2oNsI/ARVApOK3grNgqvwH6YoVYVXjNJEo5sQJsPsdV/hk" +
            "dwIDAQAB"), StrongSignatureTail.None),
        // Warcraft III maps
        (ParsePublicKey(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1BwklUUQ3UvjizOBRoF5" +
            "yyOVc7KD+oGOQH5i6eUk1yfs0luCC70kNucNrfqhmviywVtahRse1JtXCPrx2bd3" +
            "iN8Dx91fbkxjYIOGTsjYoHKTp0BbaFkJih776fcHgnFSb+7mJcDuJVvJOXxEH6w0" +
            "1vo6VtujCqj1arqbyoal+xtAaczF3us5cOEp45sR1zAWTn1+7omN7VWV4QqJPaDS" +
            "gBSESc0l1grO0i1VUSumayk7yBKIkb+LBvcG6WnYZHCi7VdLmaxER5m8oZfER66b" +
            "heHoiSQIZf9PAY6Guw2DT5BTc54j/AaLQAKf2qcRSgQLVo5kQaddF3rCpsXoB/74" +
            "6QIDAQAB"), StrongSignatureTail.FileName),
        // WoW patches
        (ParsePublicKey(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOsMV0LagAWPEtEQM6b9" +
            "6FHFkUyGbbyda2/Dfc9dyl21E9QvX+Yw7qKRMAKPzA2TlQQLZKvXpnKXF/YIK5xa" +
            "5uwg9CEHCEAYolLG4xn0FUOE0E/0PuuytI0p0ICe6rk00PifZzTr8na2wI/l/GnQ" +
            "bvnIVF1ck6cslATpQJ5JJVMXzoFlUABS19WESw4MXuJAS3AbMhxNWdEhVv7eO51c" +
            "yGjRLy9QjogZODZTY0fSEksgBqQxNCoYVJYI/sF5K2flDsGqrIp0OdJ6teJlzg1Y" +
            "UjYnb6bKjlidXoHEXI2TgA/mD6O3XFIt08I9s3crOCTgICq7cgX35qrZiIVWZdRv" +
            "TwIDAQAB"), StrongSignatureTail.Archive),
        // WoW survey
        (ParsePublicKey(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIt1DR6nRyyKsy2qahHe" +
            "MKLtacatn/KxieHcwH87wLBxKy+jZ0gycTmJ7SaTdBAEMDs/V5IPIXEtoqYnid2c" +
            "63TmfGDU92oc3Ph1PWUZ2PWxBhT06HYxRdbrgHw9/I29pNPi/607x+lzPORITOgU" +
            "BR6MR8au8HsQP4bn4vkJNgnSgojh48/XQOB/cAln7As1neP61NmVimoLR4Bwi3zt" +
            "zfgrZaUpyeNCUrOYJmH09YIjbBySTtXOUidoPHjFrMsCWpr6xs8xbETbs7MJFL6a" +
            "vcUfTT67qfIZ9RsuKfnXJTIrV0kwDSjjuNXiPTmWAehSsiHIsrUXX5RNcwsSjClr" +
            "nQIDAQAB"), StrongSignatureTail.None),
        // StarCraft II maps
        (ParsePublicKey(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmk4GT8zb+ICC25a17KZB" +
            "q/ygKGJ2VSO6IT5PGHJlm1KfnHBA4B6SH3xMlJ4c6eG2k7QevZv+FOhjsAHubyWq" +
            "2VKqWbrIFKv2ILc2RfMn8J9EDVRxvcxh6slRrVL69D0w1tfVGjMiKq2Fym5yGoRT" +
            "E7CRgDqbAbXP9LBsCNWHiJLwfxMGzHbk8pIl9oia5pvM7ofZamSHchxlpy6xa4GJ" +
            "7xKN01YCNvklTL1D7uol3wkwcHc7vrF8QwuJizuA5bSg4poEGtH62BZOYi+UL/z0" +
            "31YK+k9CbQyM0X0pJoJoYz1TK+Y5J7vBnXCZtfcTYQ/ZzN6UcxTa57dJaiOlCh9z" +
            "nQIDAQAB"), StrongSignatureTail.None),
    ];

    // DER DigestInfo prefix for MD5 (EMSA-PKCS1-v1_5).
    private static readonly byte[] Md5DigestInfo = [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10];

    /// <summary>
    /// StormLib SSignFileFinish: the (signature) file content, 8 zero bytes and the PKCS#1 v1.5 MD5 signature with its
    /// bytes reversed.
    /// </summary>
    public static byte[] SignWeak(ReadOnlySpan<byte> md5, RsaKey key)
    {
        var message = new BigInteger(EncodePkcs1Md5(md5, key.Size), isUnsigned: true, isBigEndian: true);
        var signature = BigInteger.ModPow(message, key.PrivateExponent!.Value, key.Modulus);
        var output = new byte[FileSize];
        WriteLittleEndian(signature, output.AsSpan(8, WeakSize));
        return output;
    }

    /// <summary>
    /// StormLib VerifyWeakSignature for the 72-byte (signature) file content. The decoding is as lenient as the
    /// libtomcrypt StormLib uses (pkcs_1_v1_5_decode + der_decode_sequence in rsa_verify_hash_ex): the 0xFF padding may
    /// be shorter than 8 bytes and the DigestInfo is decoded, not compared byte by byte.
    /// </summary>
    public static bool VerifyWeak(ReadOnlySpan<byte> signatureFile, ReadOnlySpan<byte> md5, RsaKey key)
    {
        var signature = new BigInteger(signatureFile.Slice(8, WeakSize), isUnsigned: true, isBigEndian: false);
        if (signature >= key.Modulus)
            return false;
        byte[] message = ToBigEndian(BigInteger.ModPow(signature, key.Exponent, key.Modulus), key.Size);
        if (message[0] != 0x00 || message[1] != 0x01)
            return false;
        int separator = 2;
        while (separator < message.Length - 1 && message[separator] == 0xFF)
            separator++;
        if (message[separator] != 0x00)
            return false;

        try
        {
            var digestInfo = new AsnReader(message.AsMemory(separator + 1), AsnEncodingRules.BER).ReadSequence();
            var algorithm = digestInfo.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != Md5Oid)
                return false;
            algorithm.ReadNull();
            return digestInfo.ReadOctetString().AsSpan().SequenceEqual(md5);
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private const string Md5Oid = "1.2.840.113549.2.5";

    /// <summary>StormLib IsValidSignature: the first 64 bytes of the (signature) file are not all zero.</summary>
    public static bool IsWeakSigned(ReadOnlySpan<byte> signatureFile) => signatureFile[..WeakSize].IndexOfAnyExcept((byte)0) >= 0;

    /// <summary>
    /// StormLib VerifyStrongSignatureWithKey: s^e mod n must equal 0x0B, 0xBB padding and the SHA-1 with its bytes
    /// reversed. <paramref name="signature"/> is the 256 bytes after "NGIS", stored little-endian.
    /// </summary>
    public static bool VerifyStrong(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> sha1, RsaKey key)
    {
        if (key.Size != StrongSize)
            return false;
        var value = new BigInteger(signature, isUnsigned: true, isBigEndian: false);
        if (value >= key.Modulus)
            return false;
        byte[] message = ToBigEndian(BigInteger.ModPow(value, key.Exponent, key.Modulus), StrongSize);
        return message.AsSpan().SequenceEqual(StrongPadding(sha1));
    }

    /// <summary>The value a strong signature decrypts to.</summary>
    public static byte[] StrongPadding(ReadOnlySpan<byte> sha1)
    {
        var padded = new byte[StrongSize];
        padded.AsSpan().Fill(0xBB);
        padded[0] = 0x0B;
        var digest = padded.AsSpan(StrongSize - sha1.Length);
        sha1.CopyTo(digest);
        digest.Reverse();
        return padded;
    }

    /// <summary>
    /// StormLib AddTailToSha1: the tail through AsciiToUpperTable (a-z upper case, '/' to '\'). Characters are truncated
    /// to bytes like GetPlainAnsiFileName does.
    /// </summary>
    public static byte[] Tail(string tail)
    {
        var bytes = new byte[tail.Length];
        for (int i = 0; i < tail.Length; i++)
        {
            byte c = (byte)tail[i];
            bytes[i] = c switch
            {
                >= (byte)'a' and <= (byte)'z' => (byte)(c - 0x20),
                (byte)'/' => (byte)'\\',
                _ => c,
            };
        }
        return bytes;
    }

    public static void WriteLittleEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out _, isUnsigned: true, isBigEndian: false);
    }

    private static byte[] ToBigEndian(BigInteger value, int size)
    {
        var output = new byte[size];
        value.TryWriteBytes(output.AsSpan(size - value.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true);
        return output;
    }

    private static byte[] EncodePkcs1Md5(ReadOnlySpan<byte> md5, int size)
    {
        var encoded = new byte[size];
        encoded[1] = 0x01;
        int digestStart = size - Md5DigestInfo.Length - md5.Length;
        encoded.AsSpan(2, digestStart - 3).Fill(0xFF);
        Md5DigestInfo.CopyTo(encoded, digestStart);
        md5.CopyTo(encoded.AsSpan(digestStart + Md5DigestInfo.Length));
        return encoded;
    }

    /// <summary>SubjectPublicKeyInfo with an RSAPublicKey.</summary>
    public static RsaKey ParsePublicKey(string base64)
    {
        var info = new AsnReader(Convert.FromBase64String(base64), AsnEncodingRules.DER).ReadSequence();
        info.ReadSequence(); // AlgorithmIdentifier
        var key = new AsnReader(info.ReadBitString(out _), AsnEncodingRules.DER).ReadSequence();
        return new RsaKey(key.ReadInteger(), key.ReadInteger());
    }

    /// <summary>PKCS#1 RSAPrivateKey (StormLib labels it "PRIVATE KEY").</summary>
    private static RsaKey ParsePrivateKey(string base64)
    {
        var key = new AsnReader(Convert.FromBase64String(base64), AsnEncodingRules.DER).ReadSequence();
        key.ReadInteger(); // version
        return new RsaKey(key.ReadInteger(), key.ReadInteger(), key.ReadInteger());
    }
}
