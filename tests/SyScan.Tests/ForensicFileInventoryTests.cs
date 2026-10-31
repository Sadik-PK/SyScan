using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SyScan.Scanner.FileSystem;
using Xunit;

namespace SyScan.Tests;

public class ForensicFileInventoryTests
{
    [Fact]
    public void IsSuspiciousExecutionPath_FlagsTempAndDownloads()
    {
        Assert.True(ForensicFileInventoryEngine.IsSuspiciousExecutionPath(@"C:\Users\Target\AppData\Local\Temp\loader.exe"));
        Assert.True(ForensicFileInventoryEngine.IsSuspiciousExecutionPath(@"C:\Windows\Temp\injector.dll"));
        Assert.True(ForensicFileInventoryEngine.IsSuspiciousExecutionPath(@"C:\Users\Target\Downloads\aimbot.exe"));

        Assert.False(ForensicFileInventoryEngine.IsSuspiciousExecutionPath(@"C:\Program Files\Game\launcher.exe"));
        Assert.False(ForensicFileInventoryEngine.IsSuspiciousExecutionPath(@"C:\Windows\System32\cmd.exe"));
    }

    [Fact]
    public async Task ScanDirectoriesAsync_FindsTargetFilesAndComputesHashes()
    {
        // Create a temporary sandbox directory with test files
        string tempDir = Path.Combine(Path.GetTempPath(), "SyScan_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // Write a test .bat and .exe file
            string batFile = Path.Combine(tempDir, "script.bat");
            await File.WriteAllTextAsync(batFile, "@echo off\r\necho SyScan Test");

            string txtFile = Path.Combine(tempDir, "document.txt");
            await File.WriteAllTextAsync(txtFile, "Ignored document");

            string subDir = Path.Combine(tempDir, "SubFolder");
            Directory.CreateDirectory(subDir);
            string ps1File = Path.Combine(subDir, "loader.ps1");
            await File.WriteAllTextAsync(ps1File, "Write-Host 'Test'");

            var engine = new ForensicFileInventoryEngine(new ForensicFileInventoryOptions
            {
                TargetExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".bat", ".ps1" },
                MaxFilesToScan = 100
            });

            var records = await engine.ScanDirectoriesAsync(new[] { tempDir }, null, CancellationToken.None);

            Assert.Equal(2, records.Count);
            Assert.Contains(records, r => r.FileName == "script.bat" && r.Sha256Hash != "hash_unavailable");
            Assert.Contains(records, r => r.FileName == "loader.ps1" && r.Sha256Hash != "hash_unavailable");
            Assert.DoesNotContain(records, r => r.FileName == "document.txt");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }
}

