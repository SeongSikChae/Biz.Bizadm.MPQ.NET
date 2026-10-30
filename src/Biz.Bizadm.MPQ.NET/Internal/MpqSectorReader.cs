using System.Runtime.InteropServices;
using Biz.Bizadm.MPQ.NET.Compression;

namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Reads, decrypts and decompresses the sectors of one file (StormLib ReadMpqSectors / ReadMpqFileSingleUnit).
/// </summary>
internal sealed class MpqSectorReader
{
    private const MpqFileFlags CompressMask = MpqFileFlags.Compress | MpqFileFlags.Implode;

    private readonly Stream _stream;
    private readonly long _filePosition;
    private readonly MpqFileEntry _entry;
    private readonly MpqFormatVersion _version;
    private readonly uint _fileKey;
    private uint[]? _sectorOffsets;

    /// <param name="headerOffset">Absolute position of the MPQ header.</param>
    /// <param name="fileKey">File key from <see cref="StormCrypto.GetFileKey"/>; required for encrypted files.</param>
    public MpqSectorReader(Stream stream, long headerOffset, MpqFileEntry entry, MpqFormatVersion version, int sectorSize, uint fileKey)
    {
        _stream = stream;
        _filePosition = headerOffset + entry.FilePosition;
        _entry = entry;
        _version = version;
        _fileKey = fileKey;

        bool singleUnit = entry.Flags.HasFlag(MpqFileFlags.SingleUnit);
        SectorSize = singleUnit ? (int)entry.FileSize : sectorSize;
        SectorCount = entry.FileSize == 0 ? 0 : singleUnit ? 1 : (int)((entry.FileSize - 1) / (uint)sectorSize) + 1;
    }

    /// <summary>Uncompressed size of a full sector; the whole file for single-unit files.</summary>
    public int SectorSize { get; }

    public int SectorCount { get; }

    public long Length => _entry.FileSize;

    private bool IsCompressed => (_entry.Flags & CompressMask) != 0;

    private bool IsEncrypted => _entry.Flags.HasFlag(MpqFileFlags.Encrypted);

    /// <summary>Uncompressed size of sector <paramref name="index"/>.</summary>
    public int GetSectorLength(int index) =>
        (int)Math.Min(SectorSize, _entry.FileSize - (long)index * SectorSize);

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
            byte[] raw = ReadRaw(_filePosition + (long)index * SectorSize, length);
            Decrypt(raw, (uint)index);
            raw.CopyTo(output);
            return length;
        }

        uint[] offsets = _sectorOffsets ??= ReadSectorOffsets();
        uint start = offsets[index], end = offsets[index + 1];
        if (end < start)
            throw new InvalidDataException($"Corrupt sector offset table (sector {index}).");

        byte[] data = ReadRaw(_filePosition + start, (int)(end - start));
        Decrypt(data, (uint)index);
        Decompress(data, output);
        return length;
    }

    public byte[] ReadAll()
    {
        var result = new byte[_entry.FileSize];
        for (int i = 0; i < SectorCount; i++)
            ReadSector(i, result.AsSpan(i * SectorSize));
        return result;
    }

    private void ReadSingleUnit(Span<byte> output)
    {
        if (!IsCompressed)
        {
            byte[] plain = ReadRaw(_filePosition, output.Length);
            Decrypt(plain, 0);
            plain.CopyTo(output);
            return;
        }

        byte[] data = ReadRaw(_filePosition, (int)_entry.CompressedSize);
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

        int written = _entry.Flags.HasFlag(MpqFileFlags.Compress)
            ? MpqCompression.Decompress(data, output, _version)
            : throw new NotSupportedException("PKWARE implode compression is not supported.");

        // StormLib: a sector that decompresses to less than expected is padded with zeros.
        output[written..].Clear();
    }

    private uint[] ReadSectorOffsets()
    {
        int count = SectorCount + 1;
        var offsets = new uint[count];
        _stream.ReadExactlyAt(_filePosition, MemoryMarshal.AsBytes(offsets.AsSpan()));
        if (IsEncrypted)
            StormCrypto.DecryptBlock(offsets, RequireKey() - 1);
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
        var buffer = new byte[length];
        _stream.ReadExactlyAt(position, buffer);
        return buffer;
    }
}
