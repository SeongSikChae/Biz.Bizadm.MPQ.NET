using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using static Biz.Bizadm.MPQ.NET.FixtureGenerator.FixtureInputs;
using static Biz.Bizadm.MPQ.NET.FixtureGenerator.StormLib;

namespace Biz.Bizadm.MPQ.NET.FixtureGenerator;

internal sealed record FixtureFile(string Name, uint Flags, uint Compression, uint? CompressionNext = null, bool Lossy = false, string? Input = null);

internal sealed record FixtureArchive(string Name, int FormatVersion, FixtureFile[] Files, bool WeakSignature = false, bool UserData = false);

internal static class Fixtures
{
    private const uint Zlib = MPQ_FILE_COMPRESS;
    private const string PatchInput = @"patch\patched.txt.bsd0";

    public const string PatchBase = "patch-base.mpq";
    public const string PatchArchive = "patch-1.mpq";

    private static FixtureFile[] Common(uint flags, uint compression) =>
    [
        new(Readme, flags, compression),
        new(FixtureInputs.Random, flags, compression),
        new(Zeros, flags, compression),
        new(Small, flags, compression),
        new(Empty, flags, compression),
    ];

    public static readonly FixtureArchive[] Archives =
    [
        // text/slash.txt: StormLib stores '/' as is (HashStringSlash), so this name is hashed with '/'.
        new("v1-zlib.mpq", 1, [.. Common(Zlib, MPQ_COMPRESSION_ZLIB), new("text/slash.txt", Zlib, MPQ_COMPRESSION_ZLIB, Input: Small)]),
        new("v1-pkware.mpq", 1, Common(MPQ_FILE_IMPLODE, 0)),
        new("v1-encrypted.mpq", 1,
        [
            new(Readme, Zlib | MPQ_FILE_ENCRYPTED, MPQ_COMPRESSION_ZLIB),
            new(FixtureInputs.Random, Zlib | MPQ_FILE_ENCRYPTED | MPQ_FILE_KEY_V2, MPQ_COMPRESSION_ZLIB),
            new(Zeros, Zlib | MPQ_FILE_ENCRYPTED | MPQ_FILE_KEY_V2 | MPQ_FILE_SINGLE_UNIT, MPQ_COMPRESSION_ZLIB),
            new(Small, MPQ_FILE_ENCRYPTED | MPQ_FILE_KEY_V2, 0),
        ]),
        new("v1-sector-options.mpq", 1,
        [
            new(Readme, Zlib | MPQ_FILE_SINGLE_UNIT, MPQ_COMPRESSION_ZLIB),
            new(Zeros, Zlib | MPQ_FILE_SECTOR_CRC, MPQ_COMPRESSION_ZLIB),
            new(FixtureInputs.Random, 0, 0),
        ]),
        new("v2-bzip2.mpq", 2, Common(Zlib, MPQ_COMPRESSION_BZIP2)),
        new("v3-lzma.mpq", 3, Common(Zlib, MPQ_COMPRESSION_LZMA)),
        new("v4-mixed.mpq", 4,
        [
            new(StereoWave, Zlib, MPQ_COMPRESSION_ZLIB, MPQ_COMPRESSION_ADPCM_STEREO | MPQ_COMPRESSION_HUFFMANN, Lossy: true),
            new(MonoWave, Zlib, MPQ_COMPRESSION_ZLIB, MPQ_COMPRESSION_ADPCM_MONO | MPQ_COMPRESSION_HUFFMANN, Lossy: true),
            new(Zeros, Zlib, MPQ_COMPRESSION_SPARSE | MPQ_COMPRESSION_ZLIB),
            new(@"data\zeros-bzip2.bin", Zlib, MPQ_COMPRESSION_SPARSE | MPQ_COMPRESSION_BZIP2, Input: Zeros),
            new(@"data\zeros-sparse.bin", Zlib, MPQ_COMPRESSION_SPARSE, Input: Zeros),
            new(@"text\pkware.txt", Zlib, MPQ_COMPRESSION_PKWARE, Input: Readme),
        ]),
        // v2+ archives only accept a fixed set of compression masks (StormLib SCompDecompress2);
        // Huffman alone and arbitrary multi-compression are v1-only.
        new("v1-legacy-masks.mpq", 1,
        [
            new(@"text\huffman.txt", Zlib, MPQ_COMPRESSION_HUFFMANN, Input: Readme),
            new(@"text\pkware-zlib.txt", Zlib, MPQ_COMPRESSION_PKWARE | MPQ_COMPRESSION_ZLIB, Input: Readme),
            new(StereoWave, Zlib, MPQ_COMPRESSION_PKWARE, MPQ_COMPRESSION_ADPCM_STEREO | MPQ_COMPRESSION_HUFFMANN, Lossy: true),
        ]),
        new("v1-weak-signed.mpq", 1, Common(Zlib, MPQ_COMPRESSION_ZLIB), WeakSignature: true),
        new("sc2-userdata.SC2Replay", 2, Common(Zlib, MPQ_COMPRESSION_ZLIB), UserData: true),
        new(PatchBase, 2, [new(Readme, Zlib, MPQ_COMPRESSION_ZLIB), new(PatchedBefore, Zlib, MPQ_COMPRESSION_ZLIB)]),
        new(PatchArchive, 2, [new(PatchedBefore, Zlib, MPQ_COMPRESSION_ZLIB, Input: PatchInput)]),
    ];

    public static readonly byte[] UserDataContent = Encoding.ASCII.GetBytes("Biz.Bizadm.MPQ.NET SC2 user data fixture\0");
    public const int UserDataHeaderOffset = 0x400;
    public const int UserDataSize = 0x200;

    public static int Generate(string outDir)
    {
        Directory.CreateDirectory(outDir);
        string inputDir = Path.Combine(Path.GetTempPath(), "mpq-fixture-inputs-" + Guid.NewGuid().ToString("N"));
        try
        {
            var inputs = new Dictionary<string, byte[]>(FixtureInputs.Create(), StringComparer.Ordinal);
            inputs[PatchInput] = CreateBsd0Patch(inputs[PatchedBefore], PatchedAfter);
            foreach (var (name, data) in inputs)
            {
                string path = Path.Combine(inputDir, name);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, data);
            }

            foreach (var archive in Archives)
            {
                string path = Path.Combine(outDir, archive.Name);
                CreateArchive(path, archive, inputDir);
                // StormLib does not open patch files outside a patch chain; see ReadPatchChainExpected.
                if (archive.Name == PatchArchive)
                    continue;
                var expected = ReadExpected(path, archive, inputs);
                expected.Save(path + ".expected.json");
                Console.WriteLine($"generated {archive.Name} ({expected.Files.Count} files)");
            }

            // The patch archive's expected file describes the whole chain (base + patch).
            var chain = ReadPatchChainExpected(outDir, inputs);
            chain.Save(Path.Combine(outDir, PatchArchive + ".expected.json"));
            Console.WriteLine($"generated {PatchArchive} chain expectations");

            SparseVectors.Generate(outDir);
            return 0;
        }
        finally
        {
            Directory.Delete(inputDir, recursive: true);
        }
    }

    private static void CreateArchive(string path, FixtureArchive archive, string inputDir)
    {
        File.Delete(path);
        var info = new SFILE_CREATE_MPQ
        {
            cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<SFILE_CREATE_MPQ>(),
            dwMpqVersion = (uint)(archive.FormatVersion - 1),
            dwFileFlags1 = MPQ_FILE_DEFAULT_INTERNAL,
            dwFileFlags2 = MPQ_FILE_DEFAULT_INTERNAL,
            // SFileSignArchive is not exported by the Windows DLL; a (signature) file created here is signed (weak) on close.
            dwFileFlags3 = archive.WeakSignature ? MPQ_FILE_DEFAULT_INTERNAL : 0,
            dwAttrFlags = MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5,
            dwSectorSize = 0x1000,
            dwRawChunkSize = archive.FormatVersion >= 4 ? 0x4000u : 0,
            dwMaxFileCount = 64,
        };
        if (!SFileCreateArchive2(path, ref info, out nint mpq))
            throw Fail($"SFileCreateArchive2({archive.Name})");
        try
        {
            foreach (var file in archive.Files)
            {
                string input = Path.Combine(inputDir, file.Input ?? file.Name);
                if (!SFileAddFileEx(mpq, input, file.Name, file.Flags | MPQ_FILE_REPLACEEXISTING, file.Compression, file.CompressionNext ?? file.Compression))
                    throw Fail($"SFileAddFileEx({archive.Name}, {file.Name})");
            }
        }
        finally
        {
            if (!SFileCloseArchive(mpq))
                throw Fail($"SFileCloseArchive({archive.Name})");
        }

        if (archive.UserData)
            PrependUserData(path);
    }

    /// <summary>Prepends an SC2-style "MPQ\x1B" user data block; MPQ offsets are relative to the MPQ header, so no fix-up is needed.</summary>
    private static void PrependUserData(string path)
    {
        byte[] mpq = File.ReadAllBytes(path);
        var prefix = new byte[UserDataHeaderOffset];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix.AsSpan(0), 0x1B51504D);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(4), UserDataSize);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(8), UserDataHeaderOffset);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(12), UserDataContent.Length);
        UserDataContent.CopyTo(prefix.AsSpan(16));
        File.WriteAllBytes(path, [.. prefix, .. mpq]);
    }

    /// <summary>
    /// Builds a "PTCH" file with a BSD0 (Blizzard bsdiff40) transform: one control entry that adds the
    /// byte-wise difference over the common length and copies the rest from the extra block.
    /// </summary>
    private static byte[] CreateBsd0Patch(byte[] before, byte[] after)
    {
        int add = Math.Min(before.Length, after.Length);
        int extra = after.Length - add;
        var diff = new byte[add];
        for (int i = 0; i < add; i++)
            diff[i] = (byte)(after[i] - before[i]);

        using var bsdiff = new MemoryStream();
        using (var w = new BinaryWriter(bsdiff, Encoding.ASCII, leaveOpen: true))
        {
            w.Write("BSDIFF40"u8);
            w.Write(12UL);              // control block size
            w.Write((ulong)add);        // data block size
            w.Write((ulong)after.Length);
            w.Write((uint)add);         // add data length
            w.Write((uint)extra);       // move (extra) data length
            w.Write(0u);                // old offset increment
            w.Write(diff);
            w.Write(after.AsSpan(add));
        }
        byte[] patchData = bsdiff.ToArray();

        // StormLib reads the patched size from RLE-compressed BSD0 data when the file is added
        // (IsIncrementalPatchFile), and decodes RLE on read only if it is smaller than the raw data.
        byte[] packed = CompressRle(patchData);
        if (packed.Length >= patchData.Length)
            throw new InvalidOperationException("RLE did not shrink the BSD0 patch data.");

        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms))
        {
            w.Write(0x48435450u);                       // 'PTCH'
            w.Write((uint)(0x44 + patchData.Length));   // size of patch data (header + transform, decompressed)
            w.Write((uint)before.Length);
            w.Write((uint)after.Length);
            w.Write(0x5F35444Du);                       // 'MD5_'
            w.Write(0x28u);
            w.Write(MD5.HashData(before));
            w.Write(MD5.HashData(after));
            w.Write(0x4D524658u);                       // 'XFRM'
            w.Write((uint)(0x0C + packed.Length));      // XFRM block: header + RLE-compressed data
            w.Write(0x30445342u);                       // 'BSD0'
            w.Write(packed);
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Inverse of StormLib Decompress_RLE: a leading DWORD (decompressed size, skipped by the reader), then
    /// 0x80|(n-1) followed by n literal bytes, or n-1 (below 0x80) for n zero bytes; n is 1..128.
    /// </summary>
    private static byte[] CompressRle(byte[] data)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((uint)data.Length);
        int i = 0;
        while (i < data.Length)
        {
            int start = i;
            if (data[i] == 0)
            {
                while (i < data.Length && data[i] == 0 && i - start < 0x80)
                    i++;
                w.Write((byte)(i - start - 1));
            }
            else
            {
                while (i < data.Length && data[i] != 0 && i - start < 0x80)
                    i++;
                w.Write((byte)(0x80 | (i - start - 1)));
                w.Write(data, start, i - start);
            }
        }
        w.Flush();
        return ms.ToArray();
    }

    private static ExpectedArchive ReadExpected(string path, FixtureArchive archive, IReadOnlyDictionary<string, byte[]> inputs)
    {
        if (!SFileOpenArchive(path, 0, MPQ_OPEN_READ_ONLY, out nint mpq))
            throw Fail($"SFileOpenArchive({archive.Name})");
        try
        {
            var files = new List<ExpectedFile>();
            foreach (var file in archive.Files)
            {
                var expected = ReadExpectedFile(mpq, file.Name, file.Lossy, isInternal: false);
                if (!file.Lossy)
                    EnsureSame(archive.Name, file.Name, inputs[file.Input ?? file.Name], expected.Sha256);
                files.Add(expected);
            }
            foreach (string name in new[] { "(listfile)", "(attributes)" })
                files.Add(ReadExpectedFile(mpq, name, lossy: false, isInternal: true));

            return new ExpectedArchive
            {
                Archive = archive.Name,
                FormatVersion = archive.FormatVersion,
                SectorSize = (int)GetUInt32Info(mpq, SFileMpqSectorSize),
                WeakSignature = archive.WeakSignature,
                UserData = archive.UserData
                    ? new ExpectedUserData { HeaderOffset = UserDataHeaderOffset, UserDataSize = UserDataSize, ContentBase64 = Convert.ToBase64String(UserDataContent) }
                    : null,
                Files = files,
            };
        }
        finally
        {
            SFileCloseArchive(mpq);
        }
    }

    private static ExpectedArchive ReadPatchChainExpected(string outDir, IReadOnlyDictionary<string, byte[]> inputs)
    {
        nint mpq = OpenChain(Path.Combine(outDir, PatchBase), [Path.Combine(outDir, PatchArchive)]);
        try
        {
            var files = new List<ExpectedFile>
            {
                ReadExpectedFile(mpq, Readme, lossy: false, isInternal: false),
                ReadExpectedFile(mpq, PatchedBefore, lossy: false, isInternal: false),
            };
            EnsureSame(PatchArchive, Readme, inputs[Readme], files[0].Sha256);
            EnsureSame(PatchArchive, PatchedBefore, PatchedAfter, files[1].Sha256);
            return new ExpectedArchive
            {
                Archive = PatchArchive,
                FormatVersion = 2,
                SectorSize = (int)GetUInt32Info(mpq, SFileMpqSectorSize),
                BaseArchive = PatchBase,
                PatchArchives = [PatchArchive],
                Files = files,
            };
        }
        finally
        {
            SFileCloseArchive(mpq);
        }
    }

    public static nint OpenChain(string basePath, IEnumerable<string> patchPaths)
    {
        if (!SFileOpenArchive(basePath, 0, MPQ_OPEN_READ_ONLY, out nint mpq))
            throw Fail($"SFileOpenArchive({basePath})");
        foreach (string patch in patchPaths)
        {
            if (!SFileOpenPatchArchive(mpq, patch, null, 0))
            {
                var error = Fail($"SFileOpenPatchArchive({patch})");
                SFileCloseArchive(mpq);
                throw error;
            }
        }
        return mpq;
    }

    public static ExpectedFile ReadExpectedFile(nint mpq, string name, bool lossy, bool isInternal)
    {
        if (!SFileOpenFileEx(mpq, name, SFILE_OPEN_FROM_MPQ, out nint file))
            throw Fail($"SFileOpenFileEx({name})");
        uint compressedSize, flags;
        try
        {
            compressedSize = GetUInt32Info(file, SFileInfoCompressedSize);
            flags = GetUInt32Info(file, SFileInfoFlags);
        }
        finally
        {
            SFileCloseFile(file);
        }

        byte[] data = StormLib.ReadFile(mpq, name);
        return new ExpectedFile
        {
            Name = name,
            Size = data.Length,
            CompressedSize = compressedSize,
            Flags = flags,
            Sha256 = Convert.ToHexString(SHA256.HashData(data)),
            Lossy = lossy,
            Internal = isInternal,
        };
    }

    private static void EnsureSame(string archive, string name, byte[] input, string sha256)
    {
        string actual = Convert.ToHexString(SHA256.HashData(input));
        if (actual != sha256)
            throw new InvalidOperationException($"{archive}: {name} read back by StormLib does not match the input.");
    }
}
