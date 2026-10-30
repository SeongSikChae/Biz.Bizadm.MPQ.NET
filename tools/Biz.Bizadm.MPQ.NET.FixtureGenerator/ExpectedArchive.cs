using System.Text.Json;
using System.Text.Json.Serialization;

namespace Biz.Bizadm.MPQ.NET.FixtureGenerator;

/// <summary>Contents of a "&lt;archive&gt;.expected.json" file written next to each fixture.</summary>
internal sealed class ExpectedArchive
{
    public required string Archive { get; init; }

    /// <summary>MPQ format version, 1..4.</summary>
    public required int FormatVersion { get; init; }

    public required int SectorSize { get; init; }

    public bool WeakSignature { get; init; }

    public ExpectedUserData? UserData { get; init; }

    /// <summary>Base archive of a patch chain; the archive itself is then the last patch.</summary>
    public string? BaseArchive { get; init; }

    public IReadOnlyList<string> PatchArchives { get; init; } = [];

    public required IReadOnlyList<ExpectedFile> Files { get; init; }

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static ExpectedArchive Load(string path) =>
        JsonSerializer.Deserialize<ExpectedArchive>(File.ReadAllText(path), JsonOptions)
        ?? throw new InvalidDataException($"Empty expected file: {path}");

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOptions));
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

    /// <summary>True when the stored data is lossy (ADPCM), so the hash is what StormLib decodes, not the input.</summary>
    public bool Lossy { get; init; }

    /// <summary>True for (listfile) and (attributes).</summary>
    public bool Internal { get; init; }
}
