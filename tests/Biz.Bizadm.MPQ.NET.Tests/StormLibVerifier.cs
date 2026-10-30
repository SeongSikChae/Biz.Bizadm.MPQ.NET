using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace Biz.Bizadm.MPQ.NET.Tests;

/// <summary>
/// Runs "FixtureGenerator verify" (StormLib) on an archive written by this library. The test is inconclusive when
/// the generator or StormLib.dll is not built (tools/build-stormlib.ps1, dotnet build of the solution).
/// </summary>
internal static class StormLibVerifier
{
    /// <param name="weakSignature">Also require SFileVerifyArchive to report a valid weak signature.</param>
    public static void AssertStormLibReads(string archivePath, MpqFormatVersion version, int sectorSize, IReadOnlyDictionary<string, byte[]> files,
        bool weakSignature = false)
    {
        string generator = FindGenerator() ?? throw new AssertInconclusiveException("FixtureGenerator is not built.");
        string expectedPath = archivePath + ".expected.json";
        var expected = new
        {
            archive = Path.GetFileName(archivePath),
            formatVersion = (int)version + 1,
            sectorSize,
            weakSignature,
            files = files.Select(f => new
            {
                name = f.Key,
                size = f.Value.Length,
                sha256 = Convert.ToHexString(SHA256.HashData(f.Value)),
            }).ToList(),
        };
        File.WriteAllText(expectedPath, JsonSerializer.Serialize(expected));

        var start = new ProcessStartInfo(generator, ["verify", archivePath, expectedPath])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(start)!;
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode == 2)
            throw new AssertInconclusiveException("StormLib is not available: " + output);
        Assert.AreEqual(0, process.ExitCode, "StormLib verify failed: " + output);
    }

    private static string? FindGenerator()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (!File.Exists(Path.Combine(dir.FullName, "Biz.Bizadm.MPQ.NET.slnx")))
                continue;
            foreach (string configuration in new[] { "Debug", "Release" })
            {
                string path = Path.Combine(dir.FullName, "tools", "Biz.Bizadm.MPQ.NET.FixtureGenerator", "bin", configuration,
                    "net10.0", "Biz.Bizadm.MPQ.NET.FixtureGenerator.exe");
                if (File.Exists(path))
                    return path;
            }
            return null;
        }
        return null;
    }
}
