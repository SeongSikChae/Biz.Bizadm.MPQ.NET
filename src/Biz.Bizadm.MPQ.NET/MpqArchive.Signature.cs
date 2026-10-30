using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

public sealed partial class MpqArchive
{
    private const int DigestUnitSize = 0x10000; // StormLib MPQ_DIGEST_UNIT_SIZE

    /// <summary>
    /// Verifies the weak (signature) file or the strong "NGIS" signature after the archive (StormLib
    /// SFileVerifyArchive). Pending changes are flushed first, so on a writable archive this writes them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only <see cref="MpqSignatureStatus.StrongValid"/> says something about who made the archive. The weak signature
    /// uses a private key that is public, so anyone (including this library on every change) can produce
    /// <see cref="MpqSignatureStatus.WeakValid"/>; it only detects accidental damage.
    /// </para>
    /// <para>
    /// The signed range starts at the MPQ header (or at the start of the file for Warcraft III maps with an "HM3W"
    /// header), so data before the header, such as StarCraft II user data, is not covered by either signature. When an
    /// archive has a (signature) file, a strong signature after the archive is not checked.
    /// </para>
    /// </remarks>
    public MpqSignatureStatus VerifySignature() => VerifySignature(MpqSignature.StrongKeys);

    /// <param name="strongKeys">Public keys for strong signatures, tried in order.</param>
    internal MpqSignatureStatus VerifySignature(IReadOnlyList<(RsaKey Key, StrongSignatureTail Tail)> strongKeys)
    {
        ThrowIfDisposed();
        lock (SyncRoot)
        {
            // StormLib QueryMpqSignatureInfo flushes a changed archive.
            if (_dirty)
                Flush();

            var (begin, end) = SignedRange(_stream);
            if (FindExisting(ListFile.SignatureName) is { CompressedSize: MpqSignature.FileSize } entry)
            {
                long position = _headerOffset + entry.FilePosition;
                var signature = new byte[MpqSignature.FileSize];
                _stream.ReadExactlyAt(position, signature);
                // A zeroed signature is not checked (StormLib reports it as valid).
                if (!MpqSignature.IsWeakSigned(signature))
                    return MpqSignatureStatus.WeakUnsigned;
                byte[] md5 = HashRange(_stream, begin, end, position, position + MpqSignature.FileSize, [], MD5.Create())[0];
                return MpqSignature.VerifyWeak(signature, md5, MpqSignature.WeakPublicKey)
                    ? MpqSignatureStatus.WeakValid
                    : MpqSignatureStatus.WeakInvalid;
            }

            if (_stream.Length - end >= MpqSignature.StrongSize + 4)
            {
                var strong = new byte[MpqSignature.StrongSize + 4];
                _stream.ReadExactlyAt(end, strong);
                // Other data may follow the archive; only "NGIS" marks a strong signature.
                if (BinaryPrimitives.ReadUInt32LittleEndian(strong) != MpqSignature.StrongId)
                    return MpqSignatureStatus.None;

                string plainName = _path is null ? "" : Path.GetFileName(_path);
                byte[][] digests = HashRange(_stream, begin, end, 0, 0,
                    [[], MpqSignature.Tail(plainName), MpqSignature.Tail("ARCHIVE")], SHA1.Create(), SHA1.Create(), SHA1.Create());
                foreach (var (key, tail) in strongKeys)
                {
                    if (MpqSignature.VerifyStrong(strong.AsSpan(4), digests[(int)tail], key))
                        return MpqSignatureStatus.StrongValid;
                }
                return MpqSignatureStatus.StrongInvalid;
            }

            return MpqSignatureStatus.None;
        }
    }

    /// <summary>
    /// Adds a weak signature (StormLib SFileSignArchive): a (signature) file is created on <see cref="Flush"/> and the
    /// archive is signed with the Blizzard weak key. A weak-signed archive is signed again after every change.
    /// </summary>
    public void SignWeak()
    {
        ThrowIfDisposed();
        EnsureWritable();
        lock (SyncRoot)
        {
            if (_signatureFlags is null)
            {
                _signatureFlags = MpqFileFlags.Exists;
                _dirty = true;
            }
        }
    }

    /// <summary>StormLib SSignFileFinish: signs the MD5 of the archive and writes it over the zeroed (signature).</summary>
    private void FinishWeakSignature(Stream target)
    {
        var entry = FindExisting(ListFile.SignatureName);
        if (entry is not { CompressedSize: MpqSignature.FileSize })
            throw new InvalidDataException("The (signature) file has an unexpected size.");

        var (begin, end) = SignedRange(target);
        long position = _headerOffset + entry.FilePosition;
        byte[] md5 = HashRange(target, begin, end, position, position + MpqSignature.FileSize, [], MD5.Create())[0];
        target.Position = position;
        target.Write(MpqSignature.SignWeak(md5, MpqSignature.WeakPrivateKey));
        target.Flush();
    }

    /// <summary>
    /// StormLib CalculateArchiveRange: from the MPQ header (or the start of the file for Warcraft III maps with an
    /// "HM3W" header) to the end of the archive.
    /// </summary>
    private (long Begin, long End) SignedRange(Stream stream)
    {
        long begin = _headerOffset;
        if (stream.Length >= 0x200)
        {
            Span<byte> magic = stackalloc byte[4];
            stream.ReadExactlyAt(0, magic);
            if (magic.SequenceEqual("HM3W"u8))
                begin = 0;
        }
        return (begin, _headerOffset + Header.ArchiveSize);
    }

    /// <summary>
    /// Hashes [<paramref name="begin"/>, <paramref name="end"/>) with [<paramref name="excludeBegin"/>,
    /// <paramref name="excludeEnd"/>) read as zero, then appends one tail per hash.
    /// </summary>
    private static byte[][] HashRange(Stream stream, long begin, long end, long excludeBegin, long excludeEnd, byte[][] tails,
        params HashAlgorithm[] hashes)
    {
        var buffer = new byte[DigestUnitSize];
        for (long position = begin; position < end;)
        {
            int count = (int)Math.Min(DigestUnitSize, end - position);
            var chunk = buffer.AsSpan(0, count);
            stream.ReadExactlyAt(position, chunk);
            long zeroBegin = Math.Max(excludeBegin, position), zeroEnd = Math.Min(excludeEnd, position + count);
            if (zeroBegin < zeroEnd)
                chunk[(int)(zeroBegin - position)..(int)(zeroEnd - position)].Clear();
            foreach (var hash in hashes)
                hash.TransformBlock(buffer, 0, count, null, 0);
            position += count;
        }

        var digests = new byte[hashes.Length][];
        for (int i = 0; i < hashes.Length; i++)
        {
            byte[] tail = i < tails.Length ? tails[i] : [];
            hashes[i].TransformFinalBlock(tail, 0, tail.Length);
            digests[i] = hashes[i].Hash!;
            hashes[i].Dispose();
        }
        return digests;
    }
}
