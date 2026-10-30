using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Biz.Bizadm.MPQ.NET.Compression;
using Biz.Bizadm.MPQ.NET.Compression.Legacy;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Reads, decrypts and decompresses the sectors of one file (StormLib ReadMpqSectors / ReadMpqFileSingleUnit).
/// </summary>
internal sealed class MpqSectorReader
{
    private const MpqFileFlags CompressMask = MpqFileFlags.Compress | MpqFileFlags.Implode;

    // StormLib TPatchInfo: dwLength, dwFlags, dwDataSize, MD5.
    private const int PatchInfoSize = 0x1C;
    private const uint PatchInfoValid = 0x80000000;

    private readonly Stream _stream;
    // Start of the file in the stream (StormLib RawFilePos); patch files have a TPatchInfo block of _patchInfoLength bytes.
    private readonly long _rawPosition;
    private readonly uint _patchInfoLength;
    private readonly MpqFileEntry _entry;
    private readonly MpqFormatVersion _version;
    private readonly uint _fileKey;
    private readonly uint _dataSize;
    private readonly uint _singleUnitSize;
    private uint[]? _sectorOffsets;

    private readonly int _maxBufferSize;

    /// <param name="stream">Archive stream (readable and seekable).</param>
    /// <param name="headerOffset">Absolute position of the MPQ header.</param>
    /// <param name="entry">File table entry for the stored file.</param>
    /// <param name="version">Archive format version (affects file offset wrapping).</param>
    /// <param name="sectorSize">Archive sector size in bytes.</param>
    /// <param name="fileKey">File key from <see cref="StormCrypto.GetFileKey"/>; required for encrypted files.</param>
    /// <param name="maxBufferSize">Largest whole-file buffer (single-unit files, <see cref="ReadAll"/>).</param>
    /// <exception cref="InvalidDataException">A single-unit file is larger than <paramref name="maxBufferSize"/>.</exception>
    public MpqSectorReader(Stream stream, long headerOffset, MpqFileEntry entry, MpqFormatVersion version, int sectorSize, uint fileKey,
        int maxBufferSize = DefaultMaxBufferSize)
    {
        _maxBufferSize = maxBufferSize;
        _stream = stream;
        _rawPosition = MpqHeaderReader.FileOffset(version, headerOffset, entry.FilePosition);
        _entry = entry;
        _version = version;
        _fileKey = fileKey;
        _dataSize = entry.FileSize;
        _singleUnitSize = entry.CompressedSize;

        if (entry.Flags.HasFlag(MpqFileFlags.PatchFile))
        {
            // StormLib AllocatePatchInfo: the data size comes from the patch info, the sectors follow it.
            var info = ReadRaw(_rawPosition, PatchInfoSize);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(info);
            if ((BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(4)) & PatchInfoValid) == 0 || length > 0x400)
                throw new InvalidDataException("Invalid patch info.");
            _dataSize = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(8));
            _patchInfoLength = length;
            // StormLib ReadMpqFileSingleUnit takes sizeof(TPatchInfo) off the compressed size.
            if (_singleUnitSize > PatchInfoSize)
                _singleUnitSize -= PatchInfoSize;
        }

        bool singleUnit = entry.Flags.HasFlag(MpqFileFlags.SingleUnit);
        // A single-unit file is one buffer of the whole file; its size comes from the archive.
        if (singleUnit)
            EnsureBufferSize(_dataSize);
        SectorSize = singleUnit ? (int)_dataSize : sectorSize;
        SectorCount = _dataSize == 0 ? 0 : singleUnit ? 1 : (int)((_dataSize - 1) / (uint)sectorSize) + 1;
    }

    /// <summary>Uncompressed size of a full sector; the whole file for single-unit files.</summary>
    public int SectorSize { get; }

    public int SectorCount { get; }

    /// <summary>Uncompressed size; for patch files the size of the patch data.</summary>
    public long Length => _dataSize;

    private bool IsCompressed => (_entry.Flags & CompressMask) != 0;

    /// <summary>
    /// StormLib CalculateRawSectorOffset: v1 positions are 32-bit (protectors use offsets that wrap), and the patch info
    /// is added after that.
    /// </summary>
    private long SectorPosition(long offset) =>
        (_version == MpqFormatVersion.Version1 ? (_rawPosition + offset) & 0xFFFFFFFF : _rawPosition + offset) + _patchInfoLength;

    private bool IsEncrypted => _entry.Flags.HasFlag(MpqFileFlags.Encrypted);

    /// <summary>Uncompressed size of sector <paramref name="index"/>.</summary>
    public int GetSectorLength(int index) =>
        (int)Math.Min(SectorSize, _dataSize - (long)index * SectorSize);

    /// <summary>Reads sector <paramref name="index"/> into <paramref name="destination"/> and returns its length.</summary>
    public int ReadSector(int index, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, SectorCount);

        int length = GetSectorLength(index);
        var output = destination[..length];

        if (_entry.Flags.HasFlag(MpqFileFlags.SingleUnit))
        {
            ReadSingleUnit(output);
            return length;
        }

        if (!IsCompressed)
        {
            byte[] raw = ReadRaw(SectorPosition((long)index * SectorSize), length);
            Decrypt(raw, (uint)index);
            raw.CopyTo(output);
            return length;
        }

        uint[] offsets = _sectorOffsets ??= ReadSectorOffsets();
        uint start = offsets[index], end = offsets[index + 1];
        byte[] data = ReadRaw(SectorPosition(start), (int)(end - start));
        Decrypt(data, (uint)index);
        Decompress(data, output);
        return length;
    }

    /// <exception cref="InvalidDataException">The file is larger than the maximum buffer size.</exception>
    public byte[] ReadAll()
    {
        EnsureBufferSize(_dataSize);
        var result = new byte[_dataSize];
        for (int i = 0; i < SectorCount; i++)
            ReadSector(i, result.AsSpan((int)((long)i * SectorSize)));
        return result;
    }

    public const int DefaultMaxBufferSize = 512 * 1024 * 1024;

    private void EnsureBufferSize(long size)
    {
        if (size > _maxBufferSize)
            throw new InvalidDataException($"The file size {size} exceeds the maximum buffer size {_maxBufferSize}.");
    }

    private void ReadSingleUnit(Span<byte> output)
    {
        if (!IsCompressed)
        {
            byte[] plain = ReadRaw(SectorPosition(0), output.Length);
            Decrypt(plain, 0);
            plain.CopyTo(output);
            return;
        }

        byte[] data = ReadRaw(SectorPosition(0), (int)_singleUnitSize);
        Decrypt(data, 0);
        Decompress(data, output);
    }

    /// <summary>A sector is compressed only when its stored size is smaller than its uncompressed size.</summary>
    private void Decompress(byte[] data, Span<byte> output)
    {
        if (data.Length >= output.Length)
        {
            data.AsSpan(0, output.Length).CopyTo(output);
            return;
        }
        if (data.Length == 0)
        {
            output.Clear();
            return;
        }

        // MPQ_FILE_IMPLODE (old style): raw PKWARE data without a compression mask byte.
        int written = _entry.Flags.HasFlag(MpqFileFlags.Compress)
            ? MpqCompression.Decompress(data, output, _version)
            : PkwareCodec.Decompress(data, output);

        // StormLib: a sector that decompresses to less than expected is padded with zeros.
        output[written..].Clear();
    }

    private uint[] ReadSectorOffsets()
    {
        int count = SectorCount + 1;
        // Checked before allocating: the sector count comes from the file size in the archive.
        if (SectorPosition(0) > _stream.Length - count * 4L)
            throw new InvalidDataException("File data lies outside the archive.");
        var offsets = new uint[count];
        _stream.ReadExactlyAt(SectorPosition(0), MemoryMarshal.AsBytes(offsets.AsSpan()));
        if (IsEncrypted)
            StormCrypto.DecryptBlock(offsets, RequireKey() - 1);

        // StormLib AllocateSectorOffsets: offsets must not decrease, a stored sector must not exceed the sector size,
        // and the first offset may exceed the table length by at most 0x400 extra bytes.
        for (int i = 0; i < SectorCount; i++)
        {
            if (offsets[i + 1] < offsets[i] || offsets[i + 1] - offsets[i] > (uint)SectorSize)
                throw new InvalidDataException("Corrupt sector offset table.");
        }
        // With MPQ_FILE_SECTOR_CRC, StormLib counts one more DWORD in the table length.
        long tableLength = (count + (_entry.Flags.HasFlag(MpqFileFlags.SectorCrc) ? 1 : 0)) * 4L;
        if ((offsets[0] & 0xFFFFFFFC) > tableLength && offsets[0] > tableLength + 0x400)
            throw new InvalidDataException("Corrupt sector offset table.");
        return offsets;
    }

    private void Decrypt(byte[] data, uint sectorIndex)
    {
        if (IsEncrypted)
            StormCrypto.DecryptBlock(data.AsSpan(), RequireKey() + sectorIndex);
    }

    private uint RequireKey() =>
        _fileKey != 0 ? _fileKey : throw new InvalidOperationException("The file is encrypted and its key is unknown.");

    private byte[] ReadRaw(long position, int length)
    {
        // Sizes come from the file and block tables; reject ones the stream cannot hold before allocating.
        if (length < 0 || position < 0 || position > _stream.Length - length)
            throw new InvalidDataException("File data lies outside the archive.");
        var buffer = new byte[length];
        _stream.ReadExactlyAt(position, buffer);
        return buffer;
    }
}
