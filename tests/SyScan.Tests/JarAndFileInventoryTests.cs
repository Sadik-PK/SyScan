using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SyScan.Scanner.FileSystem;
using SyScan.Scanner.Games;
using Xunit;

namespace SyScan.Tests;

public class JarAndFileInventoryTests : IDisposable
{
    private readonly string _tempDir;

    public JarAndFileInventoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "SyScanTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }
        catch { }
    }

    private string CreateSyntheticJar(string fileName, string? fabricModJson = null, string? manifest = null, IEnumerable<string>? dummyEntries = null)
    {
        string path = Path.Combine(_tempDir, fileName);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);

        if (manifest != null)
        {
            var mEntry = zip.CreateEntry("META-INF/MANIFEST.MF");
            using var writer = new StreamWriter(mEntry.Open(), Encoding.UTF8);
            writer.Write(manifest);
        }

        if (fabricModJson != null)
        {
            var fEntry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(fEntry.Open(), Encoding.UTF8);
            writer.Write(fabricModJson);
        }

        if (dummyEntries != null)
        {
            foreach (var de in dummyEntries)
            {
                var entry = zip.CreateEntry(de);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.WriteLine("// compiled byte code dummy");
            }
        }

        return path;
    }

    [Fact]
    public void Test1_MeteorClientInDownloads_IsIdentifiedAndClassified()
    {
        // 1. Arrange: Create Meteor Client JAR with fabric.mod.json
        string fabricJson = """
        {
          "schemaVersion": 1,
          "id": "meteor-client",
          "name": "Meteor Client",
          "version": "0.5.5",
          "description": "A Minecraft utility client.",
          "authors": ["Meteor Development"],
          "entrypoints": {
            "main": ["meteordevelopment.meteorclient.MeteorClient"]
          }
        }
        """;

        string downloadsSub = Path.Combine(_tempDir, "Downloads");
        Directory.CreateDirectory(downloadsSub);
        string jarPath = Path.Combine(downloadsSub, "meteor-client-0.5.5.jar");

        using (var fs = new FileStream(jarPath, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(fabricJson);
        }

        // 2. Act
        var result = JarAnalyzer.AnalyzeJar(jarPath);

        // 3. Assert
        Assert.True(result.IsValidZip);
        Assert.True(result.IsKnownCheatClient);
        Assert.Equal("Meteor Client", result.KnownClientName);
        Assert.NotNull(result.MinecraftMod);
        Assert.Equal("meteor-client", result.MinecraftMod!.ModId);
        Assert.Equal("0.5.5", result.MinecraftMod.Version);
        Assert.Contains("Meteor Client", result.DetectionReason);
    }

    [Fact]
    public void Test2_MeteorClientWithUnusualNameInDownloads_IsStillDiscovered()
    {
        // Name does NOT contain "meteor" or "client" — pure internal metadata discovery
        string fabricJson = """
        {
          "id": "meteor-client",
          "name": "MyCustomUtility",
          "version": "1.0.0"
        }
        """;

        string jarPath = CreateSyntheticJar("random-game-addon_992.jar", fabricJson);

        var result = JarAnalyzer.AnalyzeJar(jarPath);

        Assert.True(result.IsKnownCheatClient);
        Assert.Equal("Meteor Client", result.KnownClientName);
    }

    [Fact]
    public void Test3_CleanMinecraftMod_RemainsCleanWithoutThreatFlag()
    {
        // Sodium optimization mod — legitimate, clean
        string fabricJson = """
        {
          "id": "sodium",
          "name": "Sodium",
          "version": "0.5.8",
          "description": "Modern rendering engine for Minecraft"
        }
        """;

        string jarPath = CreateSyntheticJar("sodium-fabric-0.5.8.jar", fabricJson);

        var result = JarAnalyzer.AnalyzeJar(jarPath);

        Assert.True(result.IsValidZip);
        Assert.False(result.IsKnownCheatClient);
        Assert.NotNull(result.MinecraftMod);
        Assert.Equal("sodium", result.MinecraftMod!.ModId);
        Assert.Null(result.KnownClientName);
    }

    [Fact]
    public void Test4_UnsignedJar_IsNotClassifiedAsCheatMerelyBecauseItIsUnsigned()
    {
        // Standard unsigned java utility library
        string manifest = "Manifest-Version: 1.0\r\nMain-Class: com.example.Utility\r\n";
        string jarPath = CreateSyntheticJar("commons-helper.jar", null, manifest);

        var result = JarAnalyzer.AnalyzeJar(jarPath);

        Assert.True(result.IsValidZip);
        Assert.False(result.IsJarSigned);
        Assert.False(result.IsKnownCheatClient); // Unsigned != cheat!
        Assert.Equal("com.example.Utility", result.MainClass);
    }

    [Fact]
    public void Test5_JarSignatures_AreNotConfusedWithWindowsAuthenticode()
    {
        // JAR with META-INF signature files
        string jarPath = CreateSyntheticJar("signed-tool.jar", null, "Manifest-Version: 1.0\r\n", new[]
        {
            "META-INF/TEST.SF",
            "META-INF/TEST.RSA"
        });

        var result = JarAnalyzer.AnalyzeJar(jarPath);

        Assert.True(result.IsJarSigned);
        Assert.Equal("TEST.RSA", result.JarSignerCertificate);
    }

    [Fact]
    public async Task Test6_FileInventoryEngine_EnumeratesEveryExeAndJarAcrossNestedDirs()
    {
        // Create tree:
        // root/
        //   app.exe
        //   sub1/
        //     tool.jar
        //     driver.sys
        //     sub2/
        //       mod.jar
        //       script.bat
        string sub1 = Path.Combine(_tempDir, "sub1");
        string sub2 = Path.Combine(sub1, "sub2");
        Directory.CreateDirectory(sub2);

        await File.WriteAllTextAsync(Path.Combine(_tempDir, "app.exe"), "MZ dummy");
        CreateSyntheticJar("sub1/tool.jar", null, "Main-Class: App\r\n");
        await File.WriteAllTextAsync(Path.Combine(sub1, "driver.sys"), "SYS dummy");
        CreateSyntheticJar("sub1/sub2/mod.jar", """{"id":"fabric-api","name":"Fabric API","version":"1.0"}""");
        await File.WriteAllTextAsync(Path.Combine(sub2, "script.bat"), "@echo off");

        var engine = new ForensicFileInventoryEngine();
        var records = await engine.ScanDirectoriesAsync(new[] { _tempDir }, null, CancellationToken.None);

        Assert.True(records.Count >= 5);
        Assert.Contains(records, r => r.FileName == "app.exe" && r.ActualFileType.StartsWith("PE"));
        Assert.Contains(records, r => r.FileName == "tool.jar" && r.ActualFileType == "JAR");
        Assert.Contains(records, r => r.FileName == "driver.sys" && r.ActualFileType == "Driver");
        Assert.Contains(records, r => r.FileName == "mod.jar" && r.ActualFileType == "JAR");
        Assert.Contains(records, r => r.FileName == "script.bat" && r.ActualFileType == "BatchScript");
    }

    [Fact]
    public async Task Test7_IdenticalFiles_InMultiplePaths_AreBothPreserved()
    {
        string dirA = Path.Combine(_tempDir, "DirA");
        string dirB = Path.Combine(_tempDir, "DirB");
        Directory.CreateDirectory(dirA);
        Directory.CreateDirectory(dirB);

        string content = "MZ shared executable binary bytes";
        string pathA = Path.Combine(dirA, "tool.exe");
        string pathB = Path.Combine(dirB, "tool.exe");

        await File.WriteAllTextAsync(pathA, content);
        await File.WriteAllTextAsync(pathB, content);

        var engine = new ForensicFileInventoryEngine();
        var records = await engine.ScanDirectoriesAsync(new[] { dirA, dirB }, null, CancellationToken.None);

        Assert.Equal(2, records.Count(r => r.FileName == "tool.exe"));
        Assert.Contains(records, r => r.FullPath == pathA);
        Assert.Contains(records, r => r.FullPath == pathB);
    }

    [Fact]
    public void Test8_StreamingSha256_CalculatesCorrectHash()
    {
        string testFile = Path.Combine(_tempDir, "hash_test.bin");
        byte[] data = Encoding.UTF8.GetBytes("SyScan Forensic Streaming Hashing Test Data 2026");
        File.WriteAllBytes(testFile, data);

        string computed = JarAnalyzer.ComputeStreamingSha256(testFile);

        byte[] expectedBytes = SHA256.HashData(data);
        string expected = Convert.ToHexString(expectedBytes).ToLowerInvariant();

        Assert.Equal(expected, computed);
    }

    [Fact]
    public async Task Test9_MeteorClientInDownloads_ProducesCheatFindingAndReconciles()
    {
        // Create synthetic Downloads folder with Meteor Client
        string downloads = Path.Combine(_tempDir, "UserDownloads");
        Directory.CreateDirectory(downloads);
        string meteorPath = Path.Combine(downloads, "MeteorClient-0.5.5.jar");

        using (var fs = new FileStream(meteorPath, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("""{"id":"meteor-client","name":"Meteor Client","version":"0.5.5"}""");
        }

        var engine = new ForensicFileInventoryEngine();
        var records = await engine.ScanDirectoriesAsync(new[] { downloads }, null, CancellationToken.None);

        var meteorRecord = records.FirstOrDefault(r => r.FileName == "MeteorClient-0.5.5.jar");
        Assert.NotNull(meteorRecord);
        Assert.Equal("CheatUtility", meteorRecord!.DetectionStatus);
        Assert.Equal("minecraft", meteorRecord.AssociatedGame);
        Assert.Contains("Meteor Client", meteorRecord.DetectionNote);
    }

    [Fact]
    public void Test10_DiscoverScanRoots_ReturnsLocalFixedDriveRoots()
    {
        var roots = ForensicFileInventoryEngine.DiscoverScanRoots();

        Assert.NotEmpty(roots);
        // At least one valid drive or user directory must be returned
        Assert.Contains(roots, Directory.Exists);
    }
}
