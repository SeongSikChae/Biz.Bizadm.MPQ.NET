using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Biz.Bizadm.MPQ.NET.Internal.Patch;

/// <summary>
/// Incremental patch files ("PTCH" with a BSD0 or COPY transform) and patch chains (StormLib SFilePatchArchives.cpp).
/// </summary>
internal static class MpqPatch
{
    public const int HeaderSize = 0x44;
    private const uint PtchSignature = 0x48435450; // "PTCH"
    private const uint Md5Signature = 0x5F35444D; // "MD5_"
    private const uint XfrmSignature = 0x4D524658; // "XFRM"
    private const uint Bsd0 = 0x30445342; // "BSD0"
    private const uint Copy = 0x59504F43; // "COPY"
    private const int XfrmHeaderSize = 0x0C;
    private const int BsdiffHeaderSize = 0x20;

    /// <summary>MPQ_PATCH_HEADER.</summary>
    public readonly record struct Header(uint SizeOfPatchData, uint SizeBeforePatch, uint SizeAfterPatch, byte[] Md5Before,
        byte[] Md5After, uint XfrmBlockSize, uint PatchType, bool HasSignatures)
    {
        public static Header Read(ReadOnlySpan<byte> data)
        {
            if (data.Length < HeaderSize)
                throw new InvalidDataException("The patch file is shorter than its header.");
            static uint U(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
            return new Header(U(data, 0x04), U(data, 0x08), U(data, 0x0C), data.Slice(0x18, 16).ToArray(), data.Slice(0x28, 16).ToArray(),
                U(data, 0x3C), U(data, 0x40),
                U(data, 0x00) == PtchSignature && U(data, 0x10) == Md5Signature && U(data, 0x38) == XfrmSignature);
        }
    }

    /// <summary>
    /// StormLib Patch_Process: applies the patches to <paramref name="baseData"/> in order. A patch is skipped when the next
    /// one patches the same version (its md5_before equals the current MD5).
    /// </summary>
    /// <param name="baseMd5">MD5 of the base file from (attributes); null when unknown.</param>
    /// <param name="maxFileSize">Largest file size in the chain (StormLib Patch_InitPatcher buffer size).</param>
    /// <exception cref="InvalidDataException">A patch is corrupt or the patched data does not match its MD5.</exception>
    public static byte[] ApplyChain(byte[] baseData, byte[]? baseMd5, IReadOnlyList<byte[]> patchFiles, uint maxFileSize)
    {
        byte[] data = baseData;
        byte[] thisMd5 = baseMd5 ?? new byte[16];
        for (int i = 0; i < patchFiles.Count; i++)
        {
            while (i + 1 < patchFiles.Count && Header.Read(patchFiles[i + 1]).Md5Before.AsSpan().SequenceEqual(thisMd5))
                i++;

            var header = Header.Read(patchFiles[i]);
            data = Apply(data, header, Load(patchFiles[i], header), maxFileSize);
            if (header.SizeAfterPatch != 0)
                thisMd5 = header.Md5After;
        }
        return data;
    }

    /// <summary>StormLib LoadFullFilePatch: the transform data after the header (RLE-decoded for BSD0 when smaller).</summary>
    private static byte[] Load(byte[] patchFile, Header header)
    {
        // StormLib allocates SizeOfPatchData and fails when it cannot.
        if (!header.HasSignatures || header.SizeOfPatchData < HeaderSize || header.SizeOfPatchData - HeaderSize > Array.MaxLength)
            throw new InvalidDataException("Invalid patch header.");

        int size = (int)(header.SizeOfPatchData - HeaderSize);
        var body = patchFile.AsSpan(HeaderSize);
        switch (header.PatchType)
        {
            case Copy:
                return body.Length >= size ? body[..size].ToArray() : throw new InvalidDataException("The patch data is truncated.");

            case Bsd0:
                uint compressed = header.XfrmBlockSize - XfrmHeaderSize;
                if (compressed < (uint)size)
                {
                    if (body.Length < compressed)
                        throw new InvalidDataException("The patch data is truncated.");
                    var decompressed = new byte[size];
                    DecompressRle(decompressed, body[..(int)compressed]);
                    return decompressed;
                }
                return body.Length >= size ? body[..size].ToArray() : throw new InvalidDataException("The patch data is truncated.");

            default:
                throw new InvalidDataException("Unknown patch type.");
        }
    }

    /// <summary>
    /// StormLib Decompress_RLE: skips a leading DWORD; 0x80|(n-1) copies n literal bytes, n-1 leaves n zero bytes.
    /// </summary>
    public static void DecompressRle(Span<byte> output, ReadOnlySpan<byte> input)
    {
        output.Clear();
        int i = 4, o = 0;
        while (i < input.Length && o < output.Length)
        {
            byte b = input[i++];
            if ((b & 0x80) != 0)
            {
                for (int n = (b & 0x7F) + 1; n > 0 && o < output.Length && i < input.Length; n--)
                    output[o++] = input[i++];
            }
            else
            {
                o += b + 1;
            }
        }
    }

    /// <summary>StormLib ApplyFilePatch: applies one transform and checks md5_after_patch (unless it is zero).</summary>
    private static byte[] Apply(byte[] source, Header header, byte[] transform, uint maxFileSize)
    {
        byte[] target = header.PatchType == Copy ? ApplyCopy(transform, header) : ApplyBsd0(source, transform, header, maxFileSize);
        if (header.SizeAfterPatch != 0 && header.Md5After.AsSpan().IndexOfAnyExcept((byte)0) >= 0
            && !MD5.HashData(target.AsSpan(0, (int)Math.Min(header.SizeAfterPatch, (uint)target.Length))).AsSpan().SequenceEqual(header.Md5After))
            throw new InvalidDataException("The patched file does not match its MD5.");
        return target;
    }

    /// <summary>
    /// COPY: the data after the header is the new file. (StormLib ApplyFilePatch_COPY copies the previous version instead,
    /// so StormLib cannot apply these patches.)
    /// </summary>
    private static byte[] ApplyCopy(byte[] transform, Header header) =>
        transform.Length == header.SizeAfterPatch ? transform : throw new InvalidDataException("The COPY patch size does not match.");

    /// <summary>StormLib ApplyFilePatch_BSD0 (Blizzard bsdiff40 with 32-bit control entries), with its bounds checks.</summary>
    private static byte[] ApplyBsd0(byte[] old, byte[] patch, Header header, uint maxFileSize)
    {
        if (patch.Length < BsdiffHeaderSize)
            throw new InvalidDataException("The BSD0 patch is truncated.");
        ulong ctrlSize = BinaryPrimitives.ReadUInt64LittleEndian(patch.AsSpan(0x08));
        ulong dataSize = BinaryPrimitives.ReadUInt64LittleEndian(patch.AsSpan(0x10));
        uint newSize = (uint)BinaryPrimitives.ReadUInt64LittleEndian(patch.AsSpan(0x18));
        if (ctrlSize > (ulong)patch.Length || dataSize > (ulong)patch.Length || BsdiffHeaderSize + ctrlSize + dataSize > (ulong)patch.Length)
            throw new InvalidDataException("The BSD0 patch is truncated.");

        int ctrl = BsdiffHeaderSize;
        int data = BsdiffHeaderSize + (int)ctrlSize;
        int extra = data + (int)dataSize;
        // StormLib patches into a buffer of the largest file size in the chain.
        if (newSize > Math.Max(maxFileSize, header.SizeAfterPatch))
            throw new InvalidDataException("The BSD0 patch is larger than the patched file.");
        var target = new byte[newSize];
        uint oldSize = (uint)old.Length;
        uint newOffset = 0, oldOffset = 0;

        while (newOffset < newSize)
        {
            if (ctrl + 12 > patch.Length)
                throw new InvalidDataException("The BSD0 control block is truncated.");
            uint add = BinaryPrimitives.ReadUInt32LittleEndian(patch.AsSpan(ctrl));
            uint move = BinaryPrimitives.ReadUInt32LittleEndian(patch.AsSpan(ctrl + 4));
            uint oldMove = BinaryPrimitives.ReadUInt32LittleEndian(patch.AsSpan(ctrl + 8));
            ctrl += 12;

            if ((ulong)newOffset + add > newSize || (long)data + add > patch.Length)
                throw new InvalidDataException("Corrupt BSD0 patch.");
            patch.AsSpan(data, (int)add).CopyTo(target.AsSpan((int)newOffset));
            data += (int)add;

            // Unsigned arithmetic like StormLib: an old offset past the old size makes the combine size huge (corrupt).
            uint combine = oldOffset + add >= oldSize ? oldSize - oldOffset : add;
            if (newOffset + combine > newSize || newOffset + combine < newOffset)
                throw new InvalidDataException("Corrupt BSD0 patch.");
            // StormLib reads outside the old data here (a wrapped old offset); treat it as corrupt.
            if ((ulong)oldOffset + combine > oldSize)
                throw new InvalidDataException("Corrupt BSD0 patch.");
            for (uint i = 0; i < combine; i++)
                target[newOffset + i] += old[oldOffset + i];

            newOffset += add;
            oldOffset += add;

            if ((ulong)newOffset + move > newSize || (long)extra + move > patch.Length)
                throw new InvalidDataException("Corrupt BSD0 patch.");
            patch.AsSpan(extra, (int)move).CopyTo(target.AsSpan((int)newOffset));
            extra += (int)move;
            newOffset += move;

            if ((oldMove & 0x80000000) != 0)
                oldMove = 0x80000000 - oldMove;
            oldOffset += oldMove;
        }

        if (newOffset != header.SizeAfterPatch)
            throw new InvalidDataException("The BSD0 patch result has the wrong size.");
        return target;
    }
}
