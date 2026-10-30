using System.Security.Cryptography;
using Biz.Bizadm.MPQ.NET.FixtureGenerator;
using static Biz.Bizadm.MPQ.NET.FixtureGenerator.StormLib;

// Exit codes: 0 = success / match, 1 = mismatch, 2 = usage or environment error (e.g. StormLib.dll missing).
try
{
    return args switch
    {
        ["generate", var outDir] => Fixtures.Generate(outDir),
        ["verify", var archive, var expected] => Verify(archive, expected),
        _ => Usage(),
    };
}
catch (DllNotFoundException ex)
{
    Console.Error.WriteLine($"StormLib.dll not found. Run tools/build-stormlib.ps1 first. {ex.Message}");
    return 2;
}

static int Usage()
{
    Console.Error.WriteLine("usage: FixtureGenerator generate <outDir>");
    Console.Error.WriteLine("       FixtureGenerator verify <archive> <expected.json>");
    return 2;
}

static int Verify(string archivePath, string expectedPath)
{
    var expected = ExpectedArchive.Load(expectedPath);
    string dir = Path.GetDirectoryName(Path.GetFullPath(expectedPath))!;
    var errors = new List<string>();

    nint mpq;
    try
    {
        mpq = expected.BaseArchive is null
            ? OpenSingle(archivePath)
            : Fixtures.OpenChain(Path.Combine(dir, expected.BaseArchive), expected.PatchArchives.Select(p => p == expected.Archive ? archivePath : Path.Combine(dir, p)));
    }
    catch (InvalidOperationException ex)
    {
        Console.Error.WriteLine($"MISMATCH open: {ex.Message}");
        return 1;
    }

    try
    {
        foreach (var file in expected.Files)
        {
            try
            {
                byte[] data = StormLib.ReadFile(mpq, file.Name);
                string sha = Convert.ToHexString(SHA256.HashData(data));
                if (data.Length != file.Size || sha != file.Sha256)
                    errors.Add($"{file.Name}: size {data.Length}/{file.Size}, sha256 {sha}/{file.Sha256}");
            }
            catch (InvalidOperationException ex)
            {
                errors.Add($"{file.Name}: {ex.Message}");
            }
        }

        if (expected.WeakSignature)
        {
            uint result = SFileVerifyArchive(mpq);
            if (result != ERROR_WEAK_SIGNATURE_OK)
                errors.Add($"weak signature: SFileVerifyArchive returned {result}");
        }
    }
    finally
    {
        SFileCloseArchive(mpq);
    }

    foreach (string error in errors)
        Console.Error.WriteLine($"MISMATCH {error}");
    Console.WriteLine(errors.Count == 0 ? $"OK {expected.Archive} ({expected.Files.Count} files)" : $"FAILED {expected.Archive} ({errors.Count} mismatches)");
    return errors.Count == 0 ? 0 : 1;
}

static nint OpenSingle(string path) =>
    SFileOpenArchive(path, 0, MPQ_OPEN_READ_ONLY, out nint mpq) ? mpq : throw Fail($"SFileOpenArchive({path})");
