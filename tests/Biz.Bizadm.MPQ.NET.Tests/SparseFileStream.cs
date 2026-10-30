namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>
/// In-memory stream that only stores the pages that were written, so archives larger than 4 GB can be tested
/// without using disk space. Unwritten bytes read as zero.
/// </summary>
internal sealed class SparseFileStream : Stream
{
    private const int PageSize = 0x10000;
    private readonly Dictionary<long, byte[]> _pages = [];
    private long _length;
    private long _position;

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => true;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => _position = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int count = (int)Math.Clamp(_length - _position, 0, buffer.Length);
        for (int done = 0; done < count;)
        {
            long page = (_position + done) / PageSize;
            int inPage = (int)((_position + done) % PageSize);
            int chunk = Math.Min(count - done, PageSize - inPage);
            if (_pages.TryGetValue(page, out byte[]? data))
                data.AsSpan(inPage, chunk).CopyTo(buffer.Slice(done, chunk));
            else
                buffer.Slice(done, chunk).Clear();
            done += chunk;
        }
        _position += count;
        return count;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        for (int done = 0; done < buffer.Length;)
        {
            long page = (_position + done) / PageSize;
            int inPage = (int)((_position + done) % PageSize);
            int chunk = Math.Min(buffer.Length - done, PageSize - inPage);
            if (!_pages.TryGetValue(page, out byte[]? data))
                _pages[page] = data = new byte[PageSize];
            buffer.Slice(done, chunk).CopyTo(data.AsSpan(inPage, chunk));
            done += chunk;
        }
        _position += buffer.Length;
        _length = Math.Max(_length, _position);
    }

    public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
    {
        SeekOrigin.Begin => offset,
        SeekOrigin.Current => _position + offset,
        _ => _length + offset,
    };

    public override void SetLength(long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < _length)
        {
            // Bytes beyond the new length must read as zero if the stream grows again.
            foreach (long page in _pages.Keys.Where(p => p * PageSize >= value).ToList())
                _pages.Remove(page);
            if (_pages.TryGetValue(value / PageSize, out byte[]? last))
                last.AsSpan((int)(value % PageSize)).Clear();
        }
        _length = value;
    }

    public override void Flush()
    {
    }
}
