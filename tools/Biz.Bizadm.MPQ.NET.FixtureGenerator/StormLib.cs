using System.Runtime.InteropServices;

namespace Biz.Bizadm.MPQ.NET.FixtureGenerator;

/// <summary>P/Invoke declarations for StormLib v9.40 (ANSI build, x64).</summary>
internal static partial class StormLib
{
    private const string Dll = "StormLib";

    public const uint MPQ_FILE_IMPLODE = 0x00000100;
    public const uint MPQ_FILE_COMPRESS = 0x00000200;
    public const uint MPQ_FILE_ENCRYPTED = 0x00010000;
    public const uint MPQ_FILE_KEY_V2 = 0x00020000;
    public const uint MPQ_FILE_SINGLE_UNIT = 0x01000000;
    public const uint MPQ_FILE_SECTOR_CRC = 0x04000000;
    public const uint MPQ_FILE_REPLACEEXISTING = 0x80000000;
    public const uint MPQ_FILE_DEFAULT_INTERNAL = 0xFFFFFFFF;

    public const uint MPQ_COMPRESSION_HUFFMANN = 0x01;
    public const uint MPQ_COMPRESSION_ZLIB = 0x02;
    public const uint MPQ_COMPRESSION_PKWARE = 0x08;
    public const uint MPQ_COMPRESSION_BZIP2 = 0x10;
    public const uint MPQ_COMPRESSION_SPARSE = 0x20;
    public const uint MPQ_COMPRESSION_ADPCM_MONO = 0x40;
    public const uint MPQ_COMPRESSION_ADPCM_STEREO = 0x80;
    public const uint MPQ_COMPRESSION_LZMA = 0x12;

    public const uint MPQ_ATTRIBUTE_CRC32 = 0x01;
    public const uint MPQ_ATTRIBUTE_FILETIME = 0x02;
    public const uint MPQ_ATTRIBUTE_MD5 = 0x04;

    public const uint MPQ_OPEN_READ_ONLY = 0x00000100;
    public const uint SFILE_OPEN_FROM_MPQ = 0;
    public const uint ERROR_WEAK_SIGNATURE_OK = 2;

    // SFileInfoClass ordinals
    public const int SFileMpqSectorSize = 35;
    public const int SFileInfoCompressedSize = 52;
    public const int SFileInfoFlags = 53;

    [StructLayout(LayoutKind.Sequential)]
    public struct SFILE_CREATE_MPQ
    {
        public uint cbSize;
        public uint dwMpqVersion;
        public nint pvUserData;
        public uint cbUserData;
        public uint dwStreamFlags;
        public uint dwFileFlags1;
        public uint dwFileFlags2;
        public uint dwFileFlags3;
        public uint dwAttrFlags;
        public uint dwSectorSize;
        public uint dwRawChunkSize;
        public uint dwMaxFileCount;
    }

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileCreateArchive2(string mpqName, ref SFILE_CREATE_MPQ createInfo, out nint mpq);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileOpenArchive(string mpqName, uint priority, uint flags, out nint mpq);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileCloseArchive(nint mpq);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileAddFileEx(nint mpq, string fileName, string archivedName, uint flags, uint compression, uint compressionNext);

    [LibraryImport(Dll, SetLastError = true)]
    public static partial uint SFileVerifyArchive(nint mpq);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileOpenPatchArchive(nint mpq, string patchMpqName, string? patchPathPrefix, uint flags);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileOpenFileEx(nint mpq, string fileName, uint searchScope, out nint file);

    [LibraryImport(Dll, SetLastError = true)]
    public static partial uint SFileGetFileSize(nint file, out uint fileSizeHigh);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe partial bool SFileReadFile(nint file, byte* buffer, uint toRead, out uint read, nint overlapped);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool SFileCloseFile(nint file);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static unsafe partial bool SFileGetFileInfo(nint mpqOrFile, int infoClass, void* fileInfo, uint cbFileInfo, out uint lengthNeeded);

    [LibraryImport(Dll)]
    public static unsafe partial int SCompCompress(byte* outBuffer, int* outSize, byte* inBuffer, int inSize, uint compressionMask, int cmpType, int cmpLevel);

    [LibraryImport(Dll)]
    public static unsafe partial int SCompDecompress(byte* outBuffer, int* outSize, byte* inBuffer, int inSize);

    public static uint GetUInt32Info(nint handle, int infoClass)
    {
        uint value;
        unsafe
        {
            if (!SFileGetFileInfo(handle, infoClass, &value, sizeof(uint), out _))
                throw Fail($"SFileGetFileInfo({infoClass})");
        }
        return value;
    }

    /// <summary>Reads a whole file from an open archive (including any patch chain).</summary>
    public static byte[] ReadFile(nint mpq, string archivedName)
    {
        if (!SFileOpenFileEx(mpq, archivedName, SFILE_OPEN_FROM_MPQ, out nint file))
            throw Fail($"SFileOpenFileEx({archivedName})");
        try
        {
            uint size = SFileGetFileSize(file, out _);
            var data = new byte[size];
            unsafe
            {
                fixed (byte* p = data)
                {
                    if (size > 0 && (!SFileReadFile(file, p, size, out uint read, 0) || read != size))
                        throw Fail($"SFileReadFile({archivedName})");
                }
            }
            return data;
        }
        finally
        {
            SFileCloseFile(file);
        }
    }

    public static InvalidOperationException Fail(string call) =>
        new($"{call} failed. StormLib error {Marshal.GetLastPInvokeError()}.");
}
