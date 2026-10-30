using System.Text.Json;

namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>Test-side model of the "&lt;archive&gt;.expected.json" files written by the FixtureGenerator.</summary>
internal sealed class ExpectedArchive
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public required string Archive { get; init; }
    public required int FormatVersion { get; init; }
    public required int SectorSize { get; init; }
    public bool WeakSignature { get; init; }
    public ExpectedUserData? UserData { get; init; }
    public string? BaseArchive { get; init; }
    public IReadOnlyList<string> PatchArchives { get; init; } = [];
    public required IReadOnlyList<ExpectedFile> Files { get; init; }

    public static ExpectedArchive Load(string archive) =>
        JsonSerializer.Deserialize<ExpectedArchive>(File.ReadAllText(TestDataPath.Get(archive + ".expected.json")), JsonOptions)
        ?? throw new InvalidDataException($"Empty expected file for {archive}.");
}

internal sealed class ExpectedUserData
{
    public required int HeaderOffset { get; init; }
    public required int UserDataSize { get; init; }
    public required string ContentBase64 { get; init; }
}

internal sealed class ExpectedFile
{
    public required string Name { get; init; }
    public required int Size { get; init; }
    public uint CompressedSize { get; init; }
    public uint Flags { get; init; }
    public required string Sha256 { get; init; }
    public bool Lossy { get; init; }
    public bool Internal { get; init; }
}
