using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Biz.Bizadm.MPQ.NET.Compression;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Builds the stored form of one file (StormLib WriteDataToMpqFile / WriteSectorOffsets / WriteSectorChecksums):
/// optional sector offset table, compressed and encrypted sectors, and the sector CRC table.
/// </summary>
internal static class MpqSectorWriter
{
    private const MpqFileFlags CompressMask = MpqFileFlags.Compress | MpqFileFlags.Implode;

    /// <param name="flags">Final block flags (already filtered).</param>
    /// <param name="sectorSize">Archive sector size; single-unit files use one sector of the file size.</param>
    /// <param name="fileKey">File key for encrypted files, 0 otherwise.</param>
    /// <param name="emptySectorCrc">
    /// StormLib WriteSectorChecksums: archives with raw chunk MD5s (v4) keep the sector CRC table empty.
    /// </param>
    /// <returns>The stored bytes; their length is the compressed size.</returns>
    public static byte[] Build(ReadOnlySpan<byte> data, MpqFileFlags flags, MpqCompressionType compression, int sectorSize, uint fileKey,
        bool emptySectorCrc = false)
    {
        // StormLib AllocateSectorBuffer: nothing is stored for empty files.
        if (data.IsEmpty)
            return [];

        bool encrypted = flags.HasFlag(MpqFileFlags.Encrypted);
        bool compressed = (flags & CompressMask) != 0;
        if (flags.HasFlag(MpqFileFlags.SingleUnit))
            sectorSize = data.Length;

        int sectorCount = (data.Length - 1) / sectorSize + 1;
        bool sectorCrc = compressed && flags.HasFlag(MpqFileFlags.SectorCrc) && !flags.HasFlag(MpqFileFlags.SingleUnit);
        bool offsetTable = compressed && !flags.HasFlag(MpqFileFlags.SingleUnit);

        using var output = new MemoryStream();
        var offsets = new uint[sectorCount + 1 + (sectorCrc ? 1 : 0)];
        var checksums = sectorCrc && !emptySectorCrc ? new uint[sectorCount] : null;
        if (offsetTable)
        {
            offsets[0] = (uint)(offsets.Length * 4);
            output.Position = offsets[0];
        }

        for (int i = 0; i < sectorCount; i++)
        {
            var sector = data.Slice(i * sectorSize, Math.Min(sectorSize, data.Length - i * sectorSize));
            byte[] stored = compressed ? CompressSector(sector, flags, compression) : sector.ToArray();

            if (checksums is not null)
                checksums[i] = Adler32.Compute(stored);
            if (encrypted)
                StormCrypto.EncryptBlock(stored.AsSpan(), fileKey + (uint)i);

            output.Write(stored);
            if (offsetTable)
                offsets[i + 1] = (uint)output.Position;
        }

        if (checksums is not null)
        {
            // StormLib WriteSectorChecksums: the CRC array is zlib-compressed (when that helps) and not encrypted.
            byte[] crcTable = new byte[checksums.Length * 4];
            for (int i = 0; i < checksums.Length; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(crcTable.AsSpan(i * 4), checksums[i]);
            byte[] packed = MpqCompression.Compress(crcTable, MpqCompressionType.Zlib);
            output.Write(packed);
            offsets[sectorCount + 1] = (uint)output.Position;
        }
        else if (sectorCrc)
        {
            offsets[sectorCount + 1] = offsets[sectorCount];
        }

        if (offsetTable)
        {
            if (encrypted)
                StormCrypto.EncryptBlock(offsets, fileKey - 1);
            output.Position = 0;
            output.Write(MemoryMarshal.AsBytes(offsets.AsSpan()));
        }

        return output.ToArray();
    }

    /// <summary>Compressed sector, or the sector itself when compression does not make it smaller.</summary>
    private static byte[] CompressSector(ReadOnlySpan<byte> sector, MpqFileFlags flags, MpqCompressionType compression)
    {
        byte[] packed = flags.HasFlag(MpqFileFlags.Implode)
            ? Compression.Legacy.PkwareCodec.Compress(sector)
            : MpqCompression.Compress(sector, compression);
        return packed.Length < sector.Length ? packed : sector.ToArray();
    }
}
