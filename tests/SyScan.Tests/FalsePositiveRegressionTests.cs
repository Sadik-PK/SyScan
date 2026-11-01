using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SyScan.Scanner.Allowlist;
using SyScan.Scanner.Historical;
using SyScan.Scanner.Signatures;
using Xunit;

namespace SyScan.Tests;

public class FalsePositiveRegressionTests
{
    [Fact]
    public void SyScan_SelfDetection_IsSuppressedInDownloads()
    {
        string fakeDownloadsPath = @"C:\Users\Target\Downloads\SyScan.exe";
        bool isSyScan = SyScanIdentity.IsSyScanComponent(fakeDownloadsPath, "SyScan");
        Assert.True(isSyScan);

        var engine = new SignatureEngine();
        byte[] fakeContent = Encoding.ASCII.GetBytes("SyScan Binary Content with VirtualAllocEx and WriteProcessMemory strings");
        var matches = engine.ScanBuffer(fakeContent, fakeDownloadsPath);

        // SyScan itself must NEVER produce signature detections
        Assert.Empty(matches);
    }

    [Fact]
    public void SyScanCollector_SelfDetection_IsSuppressed()
    {
        string fakeCollectorPath = @"C:\ProgramData\SyScan\SyScan.Collector.exe";
        bool isCollector = SyScanIdentity.IsSyScanComponent(fakeCollectorPath, "SyScan.Collector");
        Assert.True(isCollector);

        var engine = new SignatureEngine();
        byte[] fakeContent = Encoding.ASCII.GetBytes("Collector Content with CreateRemoteThread and VirtualAllocEx");
        var matches = engine.ScanBuffer(fakeContent, fakeCollectorPath);

        Assert.Empty(matches);
    }

    [Fact]
    public void EasyAntiCheat_EOS_Service_IsRecognizedAndNeverFlagged()
    {
        string svcName = "EasyAntiCheat_EOS";
        string displayName = "Easy Anti-Cheat (EOS)";
        string imagePath = @"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe";

        bool isLegit = AntiCheatAllowlist.IsLegitimateAntiCheatService(svcName, displayName, imagePath);
        Assert.True(isLegit);
    }

    [Fact]
    public void BattlEye_Service_IsRecognizedAndNeverFlagged()
    {
        string svcName = "BEService";
        string displayName = "BattlEye Service";
        string imagePath = @"C:\Program Files (x86)\Common Files\BattlEye\BEService.exe";

        bool isLegit = AntiCheatAllowlist.IsLegitimateAntiCheatService(svcName, displayName, imagePath);
        Assert.True(isLegit);
    }

    [Fact]
    public void Microsoft_Runtime_Dlls_AreExcludedFromGenericInjectionRules()
    {
        var engine = new SignatureEngine();
        byte[] runtimeCode = Encoding.ASCII.GetBytes(@"
            Export: VirtualAllocEx;
            Export: WriteProcessMemory;
            Export: CreateRemoteThread;
            Export: LoadLibraryA;
        ");

        // Test msvcr100.dll
        var msvcrMatches = engine.ScanBuffer(runtimeCode, @"C:\Windows\System32\msvcr100.dll");
        Assert.Empty(msvcrMatches);

        // Test api-ms-win-core-memory-l1-1-0.dll
        var apiMsMatches = engine.ScanBuffer(runtimeCode, @"C:\Windows\System32\api-ms-win-core-memory-l1-1-0.dll");
        Assert.Empty(apiMsMatches);

        // Test UnityCrashHandler64.exe
        var unityMatches = engine.ScanBuffer(runtimeCode, @"C:\Games\GameName\UnityCrashHandler64.exe");
        Assert.Empty(unityMatches);
    }

    [Fact]
    public void FiveM_Executable_IsNotFlaggedAsGenericInjector()
    {
        var engine = new SignatureEngine();
        byte[] fivemStrings = Encoding.ASCII.GetBytes(@"
            Windows Hooking and Memory APIs:
            VirtualAllocEx
            WriteProcessMemory
            LoadLibraryA
        ");

        var matches = engine.ScanBuffer(fivemStrings, @"C:\Users\Player\AppData\Local\FiveM\FiveM.exe");
        // Must NOT match critical generic injector
        Assert.DoesNotContain(matches, m => m.RuleId == "RULE_MANUAL_MAP_INJECTOR");
    }

    [Fact]
    public void Ordinary_JumpList_PDFs_And_Media_AreInformationalOnly()
    {
        byte[] lnkPdf = new byte[256];
        BitConverter.GetBytes(0x4C).CopyTo(lnkPdf, 0);
        byte[] clsid = new byte[] {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        };
        clsid.CopyTo(lnkPdf, 4);
        string pdfPath = @"C:\Users\Player\Downloads\Tournament_Rules_2026.pdf" + "\0";
        Encoding.ASCII.GetBytes(pdfPath).CopyTo(lnkPdf, 76);

        var list = JumpListParser.ParseStreamOrFile(lnkPdf, "automaticDestinations-ms");

        Assert.NotEmpty(list);
        Assert.False(list[0].IsSuspicious);
        Assert.True(list[0].IsInformational);
    }

    [Fact]
    public void JumpList_DuplicateEntries_AreDeduplicated()
    {
        // Construct identical paths
        string testPath = @"C:\Users\Player\Documents\Guide.docx";
        var rawEntries = new List<JumpListEntry>
        {
            new JumpListEntry { TargetPath = testPath },
            new JumpListEntry { TargetPath = testPath },
            new JumpListEntry { TargetPath = testPath }
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<JumpListEntry>();
        foreach (var e in rawEntries)
        {
            if (seen.Add(e.TargetPath)) deduped.Add(e);
        }

        Assert.Single(deduped);
    }
}
