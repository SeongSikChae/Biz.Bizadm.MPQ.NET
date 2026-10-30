using Biz.Bizadm.MPQ.NET.Internal;

namespace Biz.Bizadm.MPQ.NET;

/// <summary>
/// Read-only, seekable stream over one archive file. Sectors are decompressed on demand; access to the
/// underlying archive stream is serialized with the archive's lock, so several file streams can be read concurrently.
/// </summary>
public sealed class MpqFileStream : Stream
{
    private readonly MpqArchive _archive;
    private readonly MpqSectorReader _reader;
    // Allocated on the first read, so opening a stream does not allocate a sector-sized buffer.
    private byte[]? _sector;
    private int _cachedSector = -1;
    private int _cachedLength;
    private long _position;
    private bool _disposed;

    internal MpqFileStream(MpqArchive archive, MpqSectorReader reader)
    {
        _archive = archive;
        _reader = reader;
    }

    /// <inheritdoc />
    public override bool CanRead => !_disposed && !_archive.IsDisposed;

    /// <inheritdoc />
    public override bool CanSeek => !_disposed && !_archive.IsDisposed;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <inheritdoc />
    public override long Length
    {
        get
        {
            ThrowIfDisposed();
            return _reader.Length;
        }
    }

    /// <inheritdoc />
    public override long Position
    {
        get
        {
            ThrowIfDisposed();
            return _position;
        }
        set
        {
            ThrowIfDisposed();
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        return Read(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        ThrowIfDisposed();

        int total = 0;
        while (total < buffer.Length && _position < _reader.Length)
        {
            int index = (int)(_position / _reader.SectorSize);
            if (index != _cachedSector)
                LoadSector(index);

            int offset = (int)(_position - (long)index * _reader.SectorSize);
            int count = Math.Min(_cachedLength - offset, buffer.Length - total);
            _sector!.AsSpan(offset, count).CopyTo(buffer[total..]);
            total += count;
            _position += count;
        }
        return total;
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _reader.Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0)
            throw new IOException("An attempt was made to move the position before the beginning of the stream.");
        _position = target;
        return _position;
    }

    /// <inheritdoc />
    public override void Flush()
    {
    }

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            _archive.FileStreamClosed();
        }
        base.Dispose(disposing);
    }

    /// <summary>The stream is unusable once it or its archive is disposed.</summary>
    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _archive.ThrowIfDisposed();
    }

    private void LoadSector(int index)
    {
        _sector ??= new byte[_reader.SectorSize];
        lock (_archive.SyncRoot)
        {
            _archive.ThrowIfDisposed();
            _cachedLength = _reader.ReadSector(index, _sector);
        }
        _cachedSector = index;
    }
}
