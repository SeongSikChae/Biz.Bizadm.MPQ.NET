namespace Biz.Bizadm.MPQ.NET.Internal;

/// <summary>
/// Stored (possibly compressed) sizes of the archive tables, derived like StormLib's header normalization
/// (SBaseFileTable.cpp): v1 tables are never compressed; v2 sizes come from table positions; v3 sizes from the
/// table order (HET, BET, hash, block, hi-block); v4 sizes are in the header.
/// </summary>
internal readonly record struct MpqTableLayout(long HashTableSize, long BlockTableSize, long HetTableSize, long BetTableSize)
{
    public static MpqTableLayout From(MpqHeader header, long fileSize, long headerOffset)
    {
        long hashFull = header.HashTableSize * 16L;
        long blockFull = header.BlockTableSize * 16L;

        switch (header.FormatVersion)
        {
            // A v4 header too short for the v4 fields has no stored table sizes.
            case MpqFormatVersion.Version1:
            case MpqFormatVersion.Version4 when header.V4 is null:
                return new MpqTableLayout(hashFull, blockFull, 0, 0);

            case MpqFormatVersion.Version2:
            {
                long hash = hashFull, block = blockFull;
                if (header.BlockTablePosition >= header.HashTablePosition)
                {
                    hash = header.BlockTablePosition - header.HashTablePosition;
                    block = BlockTableSizeV2(header, fileSize - headerOffset);
                }
                return new MpqTableLayout(hash, block, 0, 0);
            }

            case MpqFormatVersion.Version3:
            {
                // MaxOffset walks down from the archive size: hi-block, block, hash, BET, HET.
                long maxOffset = header.ArchiveSize;
                long hash = hashFull, block = blockFull, het = 0, bet = 0;
                if (header.HiBlockTablePosition != 0)
                    maxOffset = header.HiBlockTablePosition;
                if (header.BlockTablePosition != 0)
                {
                    block = maxOffset - header.BlockTablePosition;
                    maxOffset = header.BlockTablePosition;
                }
                if (header.HashTablePosition != 0)
                {
                    hash = maxOffset - header.HashTablePosition;
                    maxOffset = header.HashTablePosition;
                }
                if (header.BetTablePosition != 0)
                {
                    bet = maxOffset - header.BetTablePosition;
                    maxOffset = header.BetTablePosition;
                }
                if (header.HetTablePosition != 0)
                    het = maxOffset - header.HetTablePosition;
                return new MpqTableLayout(hash, block, het, bet);
            }

            default:
                var v4 = header.V4!;
                return new MpqTableLayout(v4.HashTableSize64, v4.BlockTableSize64, v4.HetTableSize64, v4.BetTableSize64);
        }
    }

    /// <summary>StormLib DetermineBlockTableSize_V2.</summary>
    private static long BlockTableSizeV2(MpqHeader header, long archiveSize)
    {
        if (header.HiBlockTablePosition != 0)
        {
            if (header.HiBlockTablePosition > header.BlockTablePosition)
                return header.HiBlockTablePosition - header.BlockTablePosition;
        }
        else if ((header.BlockTablePosition >> 32) == 0 && (archiveSize >> 32) == 0 && header.ArchiveSize == (uint)archiveSize)
        {
            return archiveSize - header.BlockTablePosition;
        }
        return header.BlockTableSize * 16L;
    }
}
