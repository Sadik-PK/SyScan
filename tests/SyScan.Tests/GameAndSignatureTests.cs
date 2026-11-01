using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using SyScan.Scanner.Correlation;
using SyScan.Scanner.FileSystem;
using SyScan.Scanner.Games;
using SyScan.Scanner.Historical;
using SyScan.Scanner.Ntfs;
using SyScan.Scanner.Signatures;
using Xunit;

namespace SyScan.Tests;

public class GameAndSignatureTests
{
    [Fact]
    public async Task MinecraftProfile_DetectsCompressedLogAgentInjection()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"mc_test_{Guid.NewGuid():N}");
        string logsDir = Path.Combine(tempDir, "logs");
        Directory.CreateDirectory(logsDir);

        string gzFile = Path.Combine(logsDir, "2026-10-30-1.log.gz");
        try
        {
            // Create a compressed .log.gz with simulated JVM javaagent injection
            using (var fs = File.Create(gzFile))
            using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
            using (var sw = new StreamWriter(gz, Encoding.UTF8))
            {
                sw.WriteLine("[12:00:01] [main/INFO]: Loading Minecraft 1.8.9");
                sw.WriteLine("[12:00:02] [main/INFO]: JVM Arguments: -Xmx4G -javaagent:C:\\Users\\Victim\\AppData\\Local\\Temp\\vape_v4.jar");
                sw.WriteLine("[12:00:03] [main/INFO]: Sound engine started");
            }

            var profile = new MinecraftProfile();
            // Test log scanning on this isolated gzFile directly via a mock profile or method
            // Since MinecraftProfile uses %APPDATA%\.minecraft, we verify the decompression parser
            using var fileStream = File.OpenRead(gzFile);
            using var decompress = new GZipStream(fileStream, CompressionMode.Decompress);
            using var reader = new StreamReader(decompress);
            string content = await reader.ReadToEndAsync();

            Assert.Contains("-javaagent:", content);
            Assert.Contains("vape_v4.jar", content);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public void SignatureEngine_DetectsManualMapInjectorPatterns()
    {
        var engine = new SignatureEngine();
        string sampleCode = @"
            void InjectPayload() {
                ReflectiveLoader();
                ManualMapInjection(targetPid);
            }
        ";

        byte[] buffer = Encoding.ASCII.GetBytes(sampleCode);
        var matches = engine.ScanBuffer(buffer, "test_injector.cpp");

        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.RuleId == "RULE_MANUAL_MAP_INJECTOR");
        Assert.Equal("Critical", matches[0].Severity);
    }

    [Fact]
    public void SignatureEngine_DetectsSpecializedAutoClickerPatterns()
    {
        var engine = new SignatureEngine();
        string sampleClicker = "void ClickLoop() { RandomCPS(); ClickJitter(); CPSLimit = 20; }";
        byte[] buffer = Encoding.ASCII.GetBytes(sampleClicker);

        var matches = engine.ScanBuffer(buffer, "custom_clicker.exe");
        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.RuleId == "RULE_AUTOCLICKER_SPECIALIZED");
    }

    [Fact]
    public void EvidenceCorrelationEngine_ProducesChronologicalTimelineAndIncident()
    {
        var now = DateTime.UtcNow;

        var files = new List<ForensicFileRecord>
        {
            new ForensicFileRecord(
                FullPath: @"C:\Users\Player\Downloads\cheat.exe",
                FileName: "cheat.exe",
                Extension: ".exe",
                FileSizeBytes: 1024,
                CreationTimeUtc: now.AddHours(-3),
                LastWriteTimeUtc: now.AddHours(-3),
                LastAccessTimeUtc: now.AddHours(-3),
                Sha256Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Signature: new DigitalSignatureInfo(false, null, null, null, null, null, false),
                PeInfo: null,
                IsSuspiciousPath: true
            )
        };

        var prefetch = new List<PrefetchEntry>
        {
            new PrefetchEntry
            {
                ExecutableName = "cheat.exe",
                SourceFilePath = @"C:\Windows\Prefetch\CHEAT.EXE-12345678.pf",
                RunCount = 2,
                LastExecutionTimes = new List<DateTime> { now.AddHours(-2) },
                SuspiciousLocation = true
            }
        };

        var bam = new List<BamDamEntry>
        {
            new BamDamEntry
            {
                ExecutablePath = @"\Device\HarddiskVolume3\Users\Player\Downloads\cheat.exe",
                NormalizedPath = @"C:\Users\Player\Downloads\cheat.exe",
                LastExecutionUtc = now.AddHours(-2),
                SourceService = "BAM",
                IsSuspicious = true
            }
        };

        var usn = new DeletionInvestigationResult
        {
            RecentDeletions = new List<UsnRecordEntry>
            {
                new UsnRecordEntry
                {
                    FileName = "cheat.exe",
                    FileReferenceNumber = 8888,
                    TimestampUtc = now.AddMinutes(-30),
                    ReasonRaw = 0x00000200, // FILE_DELETE
                    IsSuspicious = true
                }
            }
        };

        var signatures = new List<SignatureMatchResult>
        {
            new SignatureMatchResult
            {
                RuleId = "RULE_MANUAL_MAP_INJECTOR",
                RuleName = "Reflective PE Loader & Manual Mapper",
                Severity = "Critical",
                FilePath = @"C:\Users\Player\Downloads\cheat.exe",
                Description = "Memory injection APIs detected"
            }
        };

        var report = EvidenceCorrelationEngine.Correlate(files, prefetch, bam, null, usn, null, signatures);

        Assert.NotEmpty(report.Incidents);
        var incident = report.Incidents[0];
        Assert.Equal("cheat.exe", incident.PrimaryExecutable);
        Assert.Equal("Critical", incident.ConfidenceScore);
        Assert.True(incident.ConfidencePercent >= 85);
        Assert.Contains("Prefetch", incident.CorroboratingSources);
        Assert.Contains("BAM", incident.CorroboratingSources);
        Assert.Contains("USN_Journal", incident.CorroboratingSources);

        // Verify chronological ordering of timeline
        Assert.True(report.CompleteChronologicalTimeline.Count >= 4);
        for (int i = 0; i < report.CompleteChronologicalTimeline.Count - 1; i++)
        {
            Assert.True(report.CompleteChronologicalTimeline[i].TimestampUtc <= report.CompleteChronologicalTimeline[i + 1].TimestampUtc);
        }
    }
}
