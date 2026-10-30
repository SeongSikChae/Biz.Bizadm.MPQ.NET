# Biz.Bizadm.MPQ.NET

Pure .NET library for reading and writing Blizzard MPQ archives (including StarCraft II replays and maps).

## Requirements

- .NET 10 (`net10.0`)

## Install

```bash
dotnet add package Biz.Bizadm.MPQ.NET
```

## Quick start

```csharp
using Biz.Bizadm.MPQ.NET;

using var archive = MpqArchive.Open("replay.SC2Replay");
foreach (var entry in archive.Entries)
    Console.WriteLine(entry.Name);

using var stream = archive.OpenFile("replay.details");
// read stream...

using var created = MpqArchive.Create("out.mpq");
using var content = File.OpenRead("file.bin");
created.AddFile("file.bin", content);
created.Flush();
```

## Capabilities

- MPQ format versions 1–4 and SC2 user-data header (`MPQ\x1B`)
- Compression: zlib, bzip2, LZMA, and legacy codecs (PKWARE, Huffman, ADPCM, sparse)
- `(listfile)` / `(attributes)` management; weak signature verify/sign; patch archive chains

## License

MIT. See `LICENSE` and `THIRD-PARTY-NOTICES.md` in the repository root.
