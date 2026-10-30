using System.Buffers.Binary;
using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

public sealed partial class MpqArchive
{
    private const int DigestUnitSize = 0x10000; // StormLib MPQ_DIGEST_UNIT_SIZE

    /// <summary>
    /// Verifies the weak (signature) file or the strong "NGIS" signature after the archive (StormLib
    /// SFileVerifyArchive). Pending changes are flushed first.
    /// </summary>
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

            var (begin, end) = SignedRange();
            if (FindExisting(ListFile.SignatureName) is { CompressedSize: MpqSignature.FileSize } entry)
            {
                long position = _headerOffset + entry.FilePosition;
                var signature = new byte[MpqSignature.FileSize];
                _stream.ReadExactlyAt(position, signature);
                // A zeroed signature is not checked.
                if (!MpqSignature.IsWeakSigned(signature))
                    return MpqSignatureStatus.WeakValid;
                byte[] md5 = HashRange(begin, end, position, position + MpqSignature.FileSize, [], MD5.Create())[0];
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
                byte[][] digests = HashRange(begin, end, 0, 0,
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
    private void FinishWeakSignature()
    {
        var entry = FindExisting(ListFile.SignatureName);
        if (entry is not { CompressedSize: MpqSignature.FileSize })
            throw new InvalidDataException("The (signature) file has an unexpected size.");

        var (begin, end) = SignedRange();
        long position = _headerOffset + entry.FilePosition;
        byte[] md5 = HashRange(begin, end, position, position + MpqSignature.FileSize, [], MD5.Create())[0];
        _stream.Position = position;
        _stream.Write(MpqSignature.SignWeak(md5, MpqSignature.WeakPrivateKey));
        _stream.Flush();
    }

    /// <summary>
    /// StormLib CalculateArchiveRange: from the MPQ header (or the start of the file for Warcraft III maps with an
    /// "HM3W" header) to the end of the archive.
    /// </summary>
    private (long Begin, long End) SignedRange()
    {
        long begin = _headerOffset;
        if (_stream.Length >= 0x200)
        {
            Span<byte> magic = stackalloc byte[4];
            _stream.ReadExactlyAt(0, magic);
            if (magic.SequenceEqual("HM3W"u8))
                begin = 0;
        }
        return (begin, _headerOffset + Header.ArchiveSize);
    }

    /// <summary>
    /// Hashes [<paramref name="begin"/>, <paramref name="end"/>) with [<paramref name="excludeBegin"/>,
    /// <paramref name="excludeEnd"/>) read as zero, then appends one tail per hash.
    /// </summary>
    private byte[][] HashRange(long begin, long end, long excludeBegin, long excludeEnd, byte[][] tails, params HashAlgorithm[] hashes)
    {
        var buffer = new byte[DigestUnitSize];
        for (long position = begin; position < end;)
        {
            int count = (int)Math.Min(DigestUnitSize, end - position);
            var chunk = buffer.AsSpan(0, count);
            _stream.ReadExactlyAt(position, chunk);
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
