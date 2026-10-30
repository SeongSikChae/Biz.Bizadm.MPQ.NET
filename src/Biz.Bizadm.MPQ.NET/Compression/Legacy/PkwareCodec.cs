// Ported from StormLib pklib (explode.c / implode.c) and the Compress_PKLIB / Decompress_PKLIB
// wrappers in SCompression.cpp.
// MIT License, Copyright (c) 1999-2013 Ladislav Zezula.
// PKWARE Data Compression Library implementation by Ladislav Zezula.

using System.Buffers;

namespace Biz.Bizadm.MPQ.NET.Compression.Legacy;

/// <summary>
/// PKWARE Data Compression Library ("implode" / "explode"), as used by MPQ_FILE_IMPLODE files
/// and by the 0x08 compression mask.
/// </summary>
internal static class PkwareCodec
{
    // pklib.h
    private const int CmpBinary = 0;
    private const int CmpAscii = 1;

    private const int CmpImplodeDictSize1 = 1024;
    private const int CmpImplodeDictSize2 = 2048;
    private const int CmpImplodeDictSize3 = 4096;

    // Literal values returned by DecodeLit
    private const int LiteralEndOfStream = 0x305;
    private const int LiteralError = 0x306;

    // implode.c
    private const int MaxRepLength = 0x204;

    #region Tables (explode.c)

    private static readonly byte[] DistBits =
    [
        0x02, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    ];

    private static readonly byte[] DistCode =
    [
        0x03, 0x0D, 0x05, 0x19, 0x09, 0x11, 0x01, 0x3E, 0x1E, 0x2E, 0x0E, 0x36, 0x16, 0x26, 0x06, 0x3A,
        0x1A, 0x2A, 0x0A, 0x32, 0x12, 0x22, 0x42, 0x02, 0x7C, 0x3C, 0x5C, 0x1C, 0x6C, 0x2C, 0x4C, 0x0C,
        0x74, 0x34, 0x54, 0x14, 0x64, 0x24, 0x44, 0x04, 0x78, 0x38, 0x58, 0x18, 0x68, 0x28, 0x48, 0x08,
        0xF0, 0x70, 0xB0, 0x30, 0xD0, 0x50, 0x90, 0x10, 0xE0, 0x60, 0xA0, 0x20, 0xC0, 0x40, 0x80, 0x00,
    ];

    private static readonly byte[] ExLenBits =
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    private static readonly ushort[] LenBase =
    [
        0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
        0x0008, 0x000A, 0x000E, 0x0016, 0x0026, 0x0046, 0x0086, 0x0106,
    ];

    private static readonly byte[] LenBits =
    [
        0x03, 0x02, 0x03, 0x03, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x07, 0x07,
    ];

    private static readonly byte[] LenCode =
    [
        0x05, 0x03, 0x01, 0x06, 0x0A, 0x02, 0x0C, 0x14, 0x04, 0x18, 0x08, 0x30, 0x10, 0x20, 0x40, 0x00,
    ];

    private static readonly byte[] ChBitsAsc =
    [
        0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x08, 0x07, 0x0C, 0x0C, 0x07, 0x0C, 0x0C,
        0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
        0x04, 0x0A, 0x08, 0x0C, 0x0A, 0x0C, 0x0A, 0x08, 0x07, 0x07, 0x08, 0x09, 0x07, 0x06, 0x07, 0x08,
        0x07, 0x06, 0x07, 0x07, 0x07, 0x07, 0x08, 0x07, 0x07, 0x08, 0x08, 0x0C, 0x0B, 0x07, 0x09, 0x0B,
        0x0C, 0x06, 0x07, 0x06, 0x06, 0x05, 0x07, 0x08, 0x08, 0x06, 0x0B, 0x09, 0x06, 0x07, 0x06, 0x06,
        0x07, 0x0B, 0x06, 0x06, 0x06, 0x07, 0x09, 0x08, 0x09, 0x09, 0x0B, 0x08, 0x0B, 0x09, 0x0C, 0x08,
        0x0C, 0x05, 0x06, 0x06, 0x06, 0x05, 0x06, 0x06, 0x06, 0x05, 0x0B, 0x07, 0x05, 0x06, 0x05, 0x05,
        0x06, 0x0A, 0x05, 0x05, 0x05, 0x05, 0x08, 0x07, 0x08, 0x08, 0x0A, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C,
        0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
        0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
        0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
        0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
        0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
        0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
        0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D,
        0x0D, 0x0D, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    ];

    private static readonly ushort[] ChCodeAsc =
    [
        0x0490, 0x0FE0, 0x07E0, 0x0BE0, 0x03E0, 0x0DE0, 0x05E0, 0x09E0,
        0x01E0, 0x00B8, 0x0062, 0x0EE0, 0x06E0, 0x0022, 0x0AE0, 0x02E0,
        0x0CE0, 0x04E0, 0x08E0, 0x00E0, 0x0F60, 0x0760, 0x0B60, 0x0360,
        0x0D60, 0x0560, 0x1240, 0x0960, 0x0160, 0x0E60, 0x0660, 0x0A60,
        0x000F, 0x0250, 0x0038, 0x0260, 0x0050, 0x0C60, 0x0390, 0x00D8,
        0x0042, 0x0002, 0x0058, 0x01B0, 0x007C, 0x0029, 0x003C, 0x0098,
        0x005C, 0x0009, 0x001C, 0x006C, 0x002C, 0x004C, 0x0018, 0x000C,
        0x0074, 0x00E8, 0x0068, 0x0460, 0x0090, 0x0034, 0x00B0, 0x0710,
        0x0860, 0x0031, 0x0054, 0x0011, 0x0021, 0x0017, 0x0014, 0x00A8,
        0x0028, 0x0001, 0x0310, 0x0130, 0x003E, 0x0064, 0x001E, 0x002E,
        0x0024, 0x0510, 0x000E, 0x0036, 0x0016, 0x0044, 0x0030, 0x00C8,
        0x01D0, 0x00D0, 0x0110, 0x0048, 0x0610, 0x0150, 0x0060, 0x0088,
        0x0FA0, 0x0007, 0x0026, 0x0006, 0x003A, 0x001B, 0x001A, 0x002A,
        0x000A, 0x000B, 0x0210, 0x0004, 0x0013, 0x0032, 0x0003, 0x001D,
        0x0012, 0x0190, 0x000D, 0x0015, 0x0005, 0x0019, 0x0008, 0x0078,
        0x00F0, 0x0070, 0x0290, 0x0410, 0x0010, 0x07A0, 0x0BA0, 0x03A0,
        0x0240, 0x1C40, 0x0C40, 0x1440, 0x0440, 0x1840, 0x0840, 0x1040,
        0x0040, 0x1F80, 0x0F80, 0x1780, 0x0780, 0x1B80, 0x0B80, 0x1380,
        0x0380, 0x1D80, 0x0D80, 0x1580, 0x0580, 0x1980, 0x0980, 0x1180,
        0x0180, 0x1E80, 0x0E80, 0x1680, 0x0680, 0x1A80, 0x0A80, 0x1280,
        0x0280, 0x1C80, 0x0C80, 0x1480, 0x0480, 0x1880, 0x0880, 0x1080,
        0x0080, 0x1F00, 0x0F00, 0x1700, 0x0700, 0x1B00, 0x0B00, 0x1300,
        0x0DA0, 0x05A0, 0x09A0, 0x01A0, 0x0EA0, 0x06A0, 0x0AA0, 0x02A0,
        0x0CA0, 0x04A0, 0x08A0, 0x00A0, 0x0F20, 0x0720, 0x0B20, 0x0320,
        0x0D20, 0x0520, 0x0920, 0x0120, 0x0E20, 0x0620, 0x0A20, 0x0220,
        0x0C20, 0x0420, 0x0820, 0x0020, 0x0FC0, 0x07C0, 0x0BC0, 0x03C0,
        0x0DC0, 0x05C0, 0x09C0, 0x01C0, 0x0EC0, 0x06C0, 0x0AC0, 0x02C0,
        0x0CC0, 0x04C0, 0x08C0, 0x00C0, 0x0F40, 0x0740, 0x0B40, 0x0340,
        0x0300, 0x0D40, 0x1D00, 0x0D00, 0x1500, 0x0540, 0x0500, 0x1900,
        0x0900, 0x0940, 0x1100, 0x0100, 0x1E00, 0x0E00, 0x0140, 0x1600,
        0x0600, 0x1A00, 0x0E40, 0x0640, 0x0A40, 0x0A00, 0x1200, 0x0200,
        0x1C00, 0x0C00, 0x1400, 0x0400, 0x1800, 0x0800, 0x1000, 0x0000,
    ];

    #endregion

    /// <summary>
    /// Explodes <paramref name="input"/> into <paramref name="output"/> (Decompress_PKLIB).
    /// Output beyond <c>output.Length</c> is silently dropped, as StormLib's write callback does.
    /// </summary>
    /// <returns>The number of bytes written to <paramref name="output"/>.</returns>
    /// <exception cref="InvalidDataException">explode() did not return CMP_NO_ERROR.</exception>
    public static int Decompress(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var work = new Exploder(input, output);
        int result = work.Explode();
        if (result != 0)
            throw new InvalidDataException($"PKWARE DCL data is corrupt (explode error {result}).");
        return work.OutputWritten;
    }

    /// <summary>
    /// Implodes <paramref name="input"/> with the parameters Compress_PKLIB uses for MPQ data
    /// (binary mode; dictionary size chosen from the input length).
    /// </summary>
    public static byte[] Compress(ReadOnlySpan<byte> input) => Compress(input, text: false);

    /// <summary>
    /// Implodes <paramref name="input"/>. <paramref name="text"/> corresponds to Compress_PKLIB's
    /// <c>*pCmpType == DATA_TYPE_TEXT</c> and selects CMP_ASCII instead of CMP_BINARY.
    /// </summary>
    public static byte[] Compress(ReadOnlySpan<byte> input, bool text)
    {
        int ctype = text ? CmpAscii : CmpBinary;

        // Diablo I uses a fixed dictionary size of CMP_IMPLODE_DICT_SIZE3;
        // StarCraft I (and StormLib) choose it from the input length.
        int dictSize;
        if (input.Length < 0x600)
            dictSize = CmpImplodeDictSize1;
        else if (input.Length < 0xC00)
            dictSize = CmpImplodeDictSize2;
        else
            dictSize = CmpImplodeDictSize3;

        var output = new ArrayBufferWriter<byte>(Math.Max(16, input.Length / 2));
        new Imploder(output, ctype, dictSize).Implode(input);
        return output.WrittenSpan.ToArray();
    }

    #region explode.c

    private ref struct Exploder
    {
        private readonly ReadOnlySpan<byte> _input;   // read_buf source
        private readonly Span<byte> _output;          // write_buf target
        private int _inPos;                           // Position in the input data
        private int _outWritten;                      // Bytes already passed to write_buf (bounded by _output)

        private int _ctype;                           // CMP_BINARY or CMP_ASCII
        private int _outputPos;                       // Position in _outBuff
        private int _dsizeBits;                       // Dict size (4, 5, 6 for 0x400, 0x800, 0x1000)
        private int _dsizeMask;                       // Dict size bitmask (0x0F, 0x1F, 0x3F)
        private uint _bitBuff;                        // 16-bit buffer for processing input data
        private int _extraBits;                       // Number of extra (above 8) bits in bit buffer

        // 0x0000 - 0x0FFF: previous uncompressed data, kept for repetitions
        // 0x1000 - 0x1FFF: currently decompressed data
        // 0x2000 - 0x2204: reserve space for the longest possible repetition. The C struct is
        //                  0x2204 bytes and the longest repetition can write one byte past it
        //                  (into in_buff, which is never read back afterwards), so one extra byte
        //                  is reserved here.
        private readonly byte[] _outBuff;
        private readonly byte[] _distPosCodes;
        private readonly byte[] _lengthCodes;
        private readonly byte[] _offs2C34;
        private readonly byte[] _offs2D34;
        private readonly byte[] _offs2E34;
        private readonly byte[] _offs2EB4;
        private readonly byte[] _chBitsAsc;

        public Exploder(ReadOnlySpan<byte> input, Span<byte> output)
        {
            _input = input;
            _output = output;
            _outBuff = new byte[0x2205];
            _distPosCodes = new byte[0x100];
            _lengthCodes = new byte[0x100];
            _offs2C34 = new byte[0x100];
            _offs2D34 = new byte[0x100];
            _offs2E34 = new byte[0x80];
            _offs2EB4 = new byte[0x100];
            _chBitsAsc = new byte[0x100];
        }

        public readonly int OutputWritten => _outWritten;

        /// <summary>explode(): returns CMP_NO_ERROR (0) or an error code.</summary>
        public int Explode()
        {
            // The first read_buf call loads up to 0x800 bytes; fewer than 5 means bad data.
            if (_input.Length <= 4)
                return 3; // CMP_BAD_DATA

            _ctype = _input[0];           // Compression type (CMP_BINARY or CMP_ASCII)
            _dsizeBits = _input[1];       // Dictionary size
            _bitBuff = _input[2];         // Initialize 16-bit bit buffer
            _extraBits = 0;               // Extra (over 8) bits
            _inPos = 3;                   // Position in input buffer

            // Test for the valid dictionary size
            if (4 > _dsizeBits || _dsizeBits > 6)
                return 1; // CMP_INVALID_DICTSIZE

            _dsizeMask = 0xFFFF >> (0x10 - _dsizeBits);

            if (_ctype != CmpBinary)
            {
                if (_ctype != CmpAscii)
                    return 2; // CMP_INVALID_MODE

                ChBitsAsc.CopyTo(_chBitsAsc, 0);
                GenAscTabs();
            }

            GenDecodeTabs(_lengthCodes, LenCode, LenBits);
            GenDecodeTabs(_distPosCodes, DistCode, DistBits);

            if (Expand() != LiteralError)
                return 0; // CMP_NO_ERROR

            return 4; // CMP_ABORT
        }

        private static void GenDecodeTabs(byte[] positions, byte[] startIndexes, byte[] lengthBits)
        {
            for (int i = 0; i < startIndexes.Length; i++)
            {
                int length = 1 << lengthBits[i];

                for (int index = startIndexes[i]; index < 0x100; index += length)
                    positions[index] = (byte)i;
            }
        }

        private readonly void GenAscTabs()
        {
            for (int count = 0xFF; count >= 0; count--)
            {
                int code = ChCodeAsc[count];
                int bitsAsc = _chBitsAsc[count];
                int add, acc;

                if (bitsAsc <= 8)
                {
                    add = 1 << bitsAsc;
                    acc = code;

                    do
                    {
                        _offs2C34[acc] = (byte)count;
                        acc += add;
                    }
                    while (acc < 0x100);
                }
                else if ((acc = code & 0xFF) != 0)
                {
                    _offs2C34[acc] = 0xFF;

                    if ((code & 0x3F) != 0)
                    {
                        bitsAsc -= 4;
                        _chBitsAsc[count] = (byte)bitsAsc;

                        add = 1 << bitsAsc;
                        acc = code >> 4;
                        do
                        {
                            _offs2D34[acc] = (byte)count;
                            acc += add;
                        }
                        while (acc < 0x100);
                    }
                    else
                    {
                        bitsAsc -= 6;
                        _chBitsAsc[count] = (byte)bitsAsc;

                        add = 1 << bitsAsc;
                        acc = code >> 6;
                        do
                        {
                            _offs2E34[acc] = (byte)count;
                            acc += add;
                        }
                        while (acc < 0x80);
                    }
                }
                else
                {
                    bitsAsc -= 8;
                    _chBitsAsc[count] = (byte)bitsAsc;

                    add = 1 << bitsAsc;
                    acc = code >> 8;
                    do
                    {
                        _offs2EB4[acc] = (byte)count;
                        acc += add;
                    }
                    while (acc < 0x100);
                }
            }
        }

        /// <summary>
        /// Removes <paramref name="nBits"/> bits from the bit buffer, reloading from the input if needed.
        /// Returns true (PKDCL_STREAM_END) when there are no more input bytes.
        /// </summary>
        private bool WasteBits(int nBits)
        {
            if (nBits <= _extraBits)
            {
                _extraBits -= nBits;
                _bitBuff >>= nBits;
                return false;
            }

            _bitBuff >>= _extraBits;
            if (_inPos == _input.Length)
                return true;

            _bitBuff |= (uint)_input[_inPos++] << 8;
            _bitBuff >>= nBits - _extraBits;
            _extraBits = (_extraBits - nBits) + 8;
            return false;
        }

        /// <summary>
        /// Decodes the next literal: 0x000-0x0FF a byte, 0x100-0x304 a repetition of length
        /// (value - 0xFE), 0x305 end of stream, 0x306 error.
        /// </summary>
        private int DecodeLit()
        {
            if ((_bitBuff & 1) != 0)
            {
                if (WasteBits(1))
                    return LiteralError;

                // The next 8 bits hold the index to the length code table
                int lengthCode = _lengthCodes[_bitBuff & 0xFF];

                if (WasteBits(LenBits[lengthCode]))
                    return LiteralError;

                int extraLengthBits = ExLenBits[lengthCode];
                if (extraLengthBits != 0)
                {
                    int extraLength = (int)(_bitBuff & ((1u << extraLengthBits) - 1));

                    if (WasteBits(extraLengthBits))
                    {
                        // Running out of input is only allowed on the end-of-stream literal
                        if (lengthCode + extraLength != 0x10E)
                            return LiteralError;
                    }
                    lengthCode = LenBase[lengthCode] + extraLength;
                }

                return lengthCode + 0x100;
            }

            if (WasteBits(1))
                return LiteralError;

            if (_ctype == CmpBinary)
            {
                int uncompressedByte = (int)(_bitBuff & 0xFF);

                if (WasteBits(8))
                    return LiteralError;
                return uncompressedByte;
            }

            int value;
            if ((_bitBuff & 0xFF) != 0)
            {
                value = _offs2C34[_bitBuff & 0xFF];

                if (value == 0xFF)
                {
                    if ((_bitBuff & 0x3F) != 0)
                    {
                        if (WasteBits(4))
                            return LiteralError;

                        value = _offs2D34[_bitBuff & 0xFF];
                    }
                    else
                    {
                        if (WasteBits(6))
                            return LiteralError;

                        value = _offs2E34[_bitBuff & 0x7F];
                    }
                }
            }
            else
            {
                if (WasteBits(8))
                    return LiteralError;

                value = _offs2EB4[_bitBuff & 0xFF];
            }

            return WasteBits(_chBitsAsc[value]) ? LiteralError : value;
        }

        /// <summary>Decodes the backward distance of a repetition; 0 on error.</summary>
        private int DecodeDist(int repLength)
        {
            int distPosCode = _distPosCodes[_bitBuff & 0xFF];
            int distPosBits = DistBits[distPosCode];
            if (WasteBits(distPosBits))
                return 0;

            int distance;
            if (repLength == 2)
            {
                distance = (distPosCode << 2) | (int)(_bitBuff & 0x03);
                if (WasteBits(2))
                    return 0;
            }
            else
            {
                distance = (distPosCode << _dsizeBits) | (int)(_bitBuff & (uint)_dsizeMask);
                if (WasteBits(_dsizeBits))
                    return 0;
            }
            return distance + 1;
        }

        private int Expand()
        {
            int result;
            int nextLiteral;

            _outputPos = 0x1000;

            while ((result = nextLiteral = DecodeLit()) < LiteralEndOfStream)
            {
                if (nextLiteral >= 0x100)
                {
                    int repLength = nextLiteral - 0xFE;

                    int minusDist = DecodeDist(repLength);
                    if (minusDist == 0)
                    {
                        result = LiteralError;
                        break;
                    }

                    // The repeating block may overlap the current output position,
                    // so copy byte by byte.
                    int target = _outputPos;
                    int source = target - minusDist;
                    _outputPos += repLength;

                    while (repLength-- > 0)
                        _outBuff[target++] = _outBuff[source++];
                }
                else
                {
                    _outBuff[_outputPos++] = (byte)nextLiteral;
                }

                if (_outputPos >= 0x2000)
                {
                    WriteBuf(_outBuff.AsSpan(0x1000, 0x1000));

                    // Keep the data for later repetitions
                    Array.Copy(_outBuff, 0x1000, _outBuff, 0, _outputPos - 0x1000);
                    _outputPos -= 0x1000;
                }
            }

            WriteBuf(_outBuff.AsSpan(0x1000, _outputPos - 0x1000));
            return result;
        }

        /// <summary>WriteOutputData: copies as much as fits into the output buffer.</summary>
        private void WriteBuf(ReadOnlySpan<byte> data)
        {
            int toWrite = Math.Min(data.Length, _output.Length - _outWritten);
            data[..toWrite].CopyTo(_output[_outWritten..]);
            _outWritten += toWrite;
        }
    }

    #endregion

    #region implode.c

    private sealed class Imploder
    {
        private const int WorkBuffSize = 0x2204;
        private const int PhashOffsCount = 0x2204;
        private const ushort UShortMax = ushort.MaxValue;

        private readonly IBufferWriter<byte> _writer;

        private uint _distance;                       // Backward distance of the found repetition, decreased by 1
        private int _outBytes;                        // # bytes available in out_buff
        private int _outBits;                         // # of bits available in the last out byte
        private readonly int _dsizeBits;              // 4 = 0x400, 5 = 0x800, 6 = 0x1000
        private readonly int _dsizeMask;              // 0x0F, 0x1F, 0x3F
        private readonly int _ctype;                  // CMP_ASCII or CMP_BINARY
        private readonly int _dsizeBytes;             // Dictionary size in bytes
        private readonly byte[] _nChBits = new byte[0x306];
        private readonly ushort[] _nChCodes = new ushort[0x306];
        private readonly ushort[] _offs09BC = new ushort[0x204];
        private readonly ushort[] _phashToIndex = new ushort[0x900];
        private readonly byte[] _outBuff = new byte[0x802];
        private readonly byte[] _workBuff = new byte[WorkBuffSize];
        private readonly ushort[] _phashOffs = new ushort[PhashOffsCount];

        public Imploder(IBufferWriter<byte> writer, int ctype, int dsizeBytes)
        {
            _writer = writer;
            _ctype = ctype;
            _dsizeBytes = dsizeBytes;
            _dsizeBits = 4;
            _dsizeMask = 0x0F;

            switch (dsizeBytes)
            {
                case CmpImplodeDictSize3:
                    _dsizeBits += 2;
                    _dsizeMask |= 0x30;
                    break;
                case CmpImplodeDictSize2:
                    _dsizeBits += 1;
                    _dsizeMask |= 0x10;
                    break;
                case CmpImplodeDictSize1:
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(dsizeBytes));
            }

            int nCount;
            switch (ctype)
            {
                case CmpBinary:
                    for (nCount = 0; nCount < 0x100; nCount++)
                    {
                        _nChBits[nCount] = 9;
                        _nChCodes[nCount] = (ushort)(nCount * 2);
                    }
                    break;

                case CmpAscii:
                    for (nCount = 0; nCount < 0x100; nCount++)
                    {
                        _nChBits[nCount] = (byte)(ChBitsAsc[nCount] + 1);
                        _nChCodes[nCount] = (ushort)(ChCodeAsc[nCount] * 2);
                    }
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(ctype));
            }

            for (int i = 0; i < 0x10; i++)
            {
                for (int nCount2 = 0; nCount2 < (1 << ExLenBits[i]); nCount2++)
                {
                    _nChBits[nCount] = (byte)(ExLenBits[i] + LenBits[i] + 1);
                    _nChCodes[nCount] = (ushort)((nCount2 << (LenBits[i] + 1)) | (LenCode[i] * 2) | 1);
                    nCount++;
                }
            }
        }

        private static int BytePairHash(byte b0, byte b1) => (b0 * 4) + (b1 * 5);

        /// <summary>
        /// Reads the byte at <paramref name="offset"/> relative to work_buff. In the C structure
        /// work_buff is directly followed by phash_offs, and the match search near the end of the
        /// input may read past work_buff; those reads see the little-endian bytes of phash_offs.
        /// </summary>
        private byte At(int offset)
        {
            if (offset < WorkBuffSize)
                return _workBuff[offset];

            int rel = offset - WorkBuffSize;
            ushort value = _phashOffs[rel >> 1];
            return (byte)((rel & 1) == 0 ? value : value >> 8);
        }

        /// <summary>Builds phash_to_index and phash_offs for [begin, end) (offsets into work_buff).</summary>
        private void SortBuffer(int bufferBegin, int bufferEnd)
        {
            ushort totalSum = 0;

            Array.Clear(_phashToIndex);

            // Step 1: count occurrences of each PAIR_HASH
            for (int ptr = bufferBegin; ptr < bufferEnd; ptr++)
                _phashToIndex[BytePairHash(At(ptr), At(ptr + 1))]++;

            // Step 2: running totals
            for (int i = 0; i < _phashToIndex.Length; i++)
            {
                totalSum = (ushort)(totalSum + _phashToIndex[i]);
                _phashToIndex[i] = totalSum;
            }

            // Step 3: each element becomes the index of the first occurrence of its PAIR_HASH
            for (bufferEnd--; bufferEnd >= bufferBegin; bufferEnd--)
            {
                int bytePairHash = BytePairHash(At(bufferEnd), At(bufferEnd + 1));
                ushort bytePairOffs = (ushort)bufferEnd;

                _phashToIndex[bytePairHash]--;
                _phashOffs[_phashToIndex[bytePairHash]] = bytePairOffs;
            }
        }

        private void FlushBuf()
        {
            _writer.Write(_outBuff.AsSpan(0, 0x800));

            byte saveCh1 = _outBuff[0x800];
            byte saveCh2 = _outBuff[_outBytes];
            _outBytes -= 0x800;

            Array.Clear(_outBuff);

            if (_outBytes != 0)
                _outBuff[0] = saveCh1;
            if (_outBits != 0)
                _outBuff[_outBytes] = saveCh2;
        }

        private void OutputBits(int nbits, uint bitBuff)
        {
            if (nbits > 8)
            {
                OutputBits(8, bitBuff);
                bitBuff >>= 8;
                nbits -= 8;
            }

            int outBits = _outBits;
            _outBuff[_outBytes] |= (byte)(bitBuff << outBits);
            _outBits += nbits;

            if (_outBits > 8)
            {
                _outBytes++;
                bitBuff >>= 8 - outBits;

                _outBuff[_outBytes] = (byte)bitBuff;
                _outBits &= 7;
            }
            else
            {
                _outBits &= 7;
                if (_outBits == 0)
                    _outBytes++;
            }

            if (_outBytes >= 0x800)
                FlushBuf();
        }

        /// <summary>
        /// Searches for a previous occurrence of the byte sequence at <paramref name="inputData"/>.
        /// Returns the repetition length and stores the backward distance in <see cref="_distance"/>.
        /// </summary>
        private int FindRep(int inputData)
        {
            int repLength = 1;
            int equalByteCount = 0;

            int phashToIndex = BytePairHash(At(inputData), At(inputData + 1));
            ushort minPhashOffs = (ushort)(inputData - _dsizeBytes + 1);
            int phashOffsIndex = _phashToIndex[phashToIndex];

            // If the PAIR_HASH offset is below the limit, find a next one
            if (_phashOffs[phashOffsIndex] < minPhashOffs)
            {
                while (_phashOffs[phashOffsIndex] < minPhashOffs)
                    phashOffsIndex = (ushort)(phashOffsIndex + 1);
                _phashToIndex[phashToIndex] = (ushort)phashOffsIndex;
            }

            int prevRepetition = _phashOffs[phashOffsIndex];
            int repetitionLimit = inputData - 1;

            // The current PAIR_HASH was not encountered before
            if (prevRepetition >= repetitionLimit)
                return 0;

            int inputDataPtr = inputData;
            for (;;)
            {
                if (At(inputDataPtr) == At(prevRepetition) && At(inputDataPtr + repLength - 1) == At(prevRepetition + repLength - 1))
                {
                    prevRepetition++;
                    inputDataPtr++;
                    equalByteCount = 2;

                    while (equalByteCount < MaxRepLength)
                    {
                        prevRepetition++;
                        inputDataPtr++;

                        if (At(prevRepetition) != At(inputDataPtr))
                            break;

                        equalByteCount++;
                    }

                    // Take a repetition of at least the same length; this prefers the most recent one
                    inputDataPtr = inputData;
                    if (equalByteCount >= repLength)
                    {
                        _distance = (uint)(inputData - prevRepetition + equalByteCount - 1);

                        if ((repLength = equalByteCount) > 10)
                            break;
                    }
                }

                // Move forward in the table of PAIR_HASH repetitions
                phashOffsIndex = (ushort)(phashOffsIndex + 1);
                prevRepetition = _phashOffs[phashOffsIndex];

                if (prevRepetition >= repetitionLimit)
                    return repLength >= 2 ? repLength : 0;
            }

            if (equalByteCount == MaxRepLength)
            {
                _distance--;
                return equalByteCount;
            }

            // Check for possibility of a repetition that occurs at more recent position
            if (_phashOffs[phashOffsIndex + 1] >= repetitionLimit)
                return repLength;

            // Check whether a later repetition gives a longer match.
            _offs09BC[0] = UShortMax;
            _offs09BC[1] = 0x0000;
            ushort diVal = 0;

            int offsInRep;
            for (offsInRep = 1; offsInRep < repLength;)
            {
                if (At(inputData + offsInRep) != At(inputData + diVal))
                {
                    diVal = _offs09BC[diVal];
                    if (diVal != UShortMax)
                        continue;
                }
                diVal = (ushort)(diVal + 1);
                _offs09BC[++offsInRep] = diVal;
            }

            prevRepetition = _phashOffs[phashOffsIndex];
            int prevRepEnd = prevRepetition + repLength;
            int repLength2 = repLength;

            for (;;)
            {
                repLength2 = _offs09BC[repLength2];
                if (repLength2 == UShortMax)
                    repLength2 = 0;

                // Skip those repetitions that don't reach the end of the first found repetition
                do
                {
                    phashOffsIndex = (ushort)(phashOffsIndex + 1);
                    prevRepetition = _phashOffs[phashOffsIndex];
                    if (prevRepetition >= repetitionLimit)
                        return repLength;
                }
                while (prevRepetition + repLength2 < prevRepEnd);

                byte preLastByte = At(inputData + repLength - 2);
                if (preLastByte == At(prevRepetition + repLength - 2))
                {
                    // The new repetition reaches beyond the end of the previously found one
                    if (prevRepetition + repLength2 != prevRepEnd)
                    {
                        prevRepEnd = prevRepetition;
                        repLength2 = 0;
                    }
                }
                else
                {
                    do
                    {
                        phashOffsIndex = (ushort)(phashOffsIndex + 1);
                        prevRepetition = _phashOffs[phashOffsIndex];
                        if (prevRepetition >= repetitionLimit)
                            return repLength;
                    }
                    while (At(prevRepetition + repLength - 2) != preLastByte || At(prevRepetition) != At(inputData));

                    prevRepEnd = prevRepetition + 2;
                    repLength2 = 2;
                }

                // Find out how many more characters are equal to the first repetition
                while (At(prevRepEnd) == At(inputData + repLength2))
                {
                    if (++repLength2 >= MaxRepLength)
                        break;
                    prevRepEnd++;
                }

                if (repLength2 >= repLength)
                {
                    _distance = (uint)(inputData - prevRepetition - 1);
                    if ((repLength = repLength2) == MaxRepLength)
                        return repLength;

                    while (offsInRep < repLength2)
                    {
                        if (At(inputData + offsInRep) != At(inputData + diVal))
                        {
                            diVal = _offs09BC[diVal];
                            if (diVal != UShortMax)
                                continue;
                        }
                        diVal = (ushort)(diVal + 1);
                        _offs09BC[++offsInRep] = diVal;
                    }
                }
            }
        }

        private void OutputRepetition(int repLength)
        {
            OutputBits(_nChBits[repLength + 0xFE], _nChCodes[repLength + 0xFE]);
            if (repLength == 2)
            {
                OutputBits(DistBits[_distance >> 2], DistCode[_distance >> 2]);
                OutputBits(2, _distance & 3);
            }
            else
            {
                OutputBits(DistBits[_distance >> _dsizeBits], DistCode[_distance >> _dsizeBits]);
                OutputBits(_dsizeBits, (uint)_dsizeMask & _distance);
            }
        }

        private void OutputLiteral(byte value) => OutputBits(_nChBits[value], _nChCodes[value]);

        /// <summary>implode() / WriteCmpData().</summary>
        public void Implode(ReadOnlySpan<byte> source)
        {
            int sourcePos = 0;
            int inputData = _dsizeBytes + MaxRepLength;
            bool inputDataEnded = false;
            int phase = 0;

            // Store the compression type and dictionary size
            _outBuff[0] = (byte)_ctype;
            _outBuff[1] = (byte)_dsizeBits;
            _outBytes = 2;
            _outBits = 0;

            while (!inputDataEnded)
            {
                // Load up to 0x1000 bytes (ReadInputData returns what is left, then 0)
                int totalLoaded = Math.Min(0x1000, source.Length - sourcePos);
                source.Slice(sourcePos, totalLoaded).CopyTo(_workBuff.AsSpan(_dsizeBytes + MaxRepLength));
                sourcePos += totalLoaded;

                if (totalLoaded < 0x1000)
                {
                    if (totalLoaded == 0 && phase == 0)
                        break;
                    inputDataEnded = true;
                }

                int inputDataEnd = _dsizeBytes + totalLoaded;
                if (inputDataEnded)
                    inputDataEnd += MaxRepLength;

                // The end passed to SortBuffer is one byte beyond valid data, as in pklib.
                switch (phase)
                {
                    case 0:
                        SortBuffer(inputData, inputDataEnd + 1);
                        phase++;
                        if (_dsizeBytes != 0x1000)
                            phase++;
                        break;

                    case 1:
                        SortBuffer(inputData - _dsizeBytes + MaxRepLength, inputDataEnd + 1);
                        phase++;
                        break;

                    default:
                        SortBuffer(inputData - _dsizeBytes, inputDataEnd + 1);
                        break;
                }

                while (inputData < inputDataEnd)
                {
                    int repLength = FindRep(inputData);
                    bool flushed = false;

                    while (repLength != 0)
                    {
                        // A 2-byte repetition 0x100 or further back is not worth it
                        if (repLength == 2 && _distance >= 0x100)
                            break;

                        if (inputDataEnded && inputData + repLength > inputDataEnd)
                        {
                            // Shorten the repetition so that it only covers valid data
                            repLength = inputDataEnd - inputData;
                            if (repLength < 2)
                                break;

                            if (repLength == 2 && _distance >= 0x100)
                                break;
                        }
                        else if (repLength < 8 && inputData + 1 < inputDataEnd)
                        {
                            // Try to find a better repetition 1 byte later
                            int saveRepLength = repLength;
                            uint saveDistance = _distance;
                            repLength = FindRep(inputData + 1);

                            if (repLength > saveRepLength)
                            {
                                if (repLength > saveRepLength + 1 || saveDistance > 0x80)
                                {
                                    // Flush one byte, so that inputData points to the secondary repetition
                                    OutputLiteral(_workBuff[inputData]);
                                    inputData++;
                                    continue;
                                }
                            }

                            // Revert to the previous repetition
                            repLength = saveRepLength;
                            _distance = saveDistance;
                        }

                        // __FlushRepetition
                        OutputRepetition(repLength);
                        inputData += repLength;
                        flushed = true;
                        break;
                    }

                    if (!flushed)
                    {
                        // No usable repetition: output the literal byte
                        OutputLiteral(_workBuff[inputData]);
                        inputData++;
                    }
                }

                if (!inputDataEnded)
                {
                    inputData -= 0x1000;
                    Array.Copy(_workBuff, 0x1000, _workBuff, 0, _dsizeBytes + MaxRepLength);
                }
            }

            // Write the termination literal
            OutputBits(_nChBits[0x305], _nChCodes[0x305]);
            if (_outBits != 0)
                _outBytes++;
            _writer.Write(_outBuff.AsSpan(0, _outBytes));
        }
    }

    #endregion
}
