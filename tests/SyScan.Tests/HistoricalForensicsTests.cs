using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SyScan.Scanner.Historical;
using Xunit;

namespace SyScan.Tests;

public class HistoricalForensicsTests
{
    [Fact]
    public void PrefetchParser_ParsesValidWin10PrefetchData()
    {
        // Construct a synthetic Win 10 (version 30) Prefetch buffer
        byte[] buffer = new byte[512];
        BitConverter.GetBytes((uint)30).CopyTo(buffer, 0); // Version 30
        BitConverter.GetBytes(0x41434353u).CopyTo(buffer, 4); // "SCCA"
        BitConverter.GetBytes(512u).CopyTo(buffer, 8); // File size

        // Executable name at offset 0x10 (UTF-16LE, "CHEATCLIENT.EXE")
        byte[] nameBytes = Encoding.Unicode.GetBytes("CHEATCLIENT.EXE\0");
        nameBytes.CopyTo(buffer, 0x10);

        // Prefetch hash at 0x4C
        BitConverter.GetBytes(0xDEADBEEFu).CopyTo(buffer, 0x4C);

        // Section C (Strings): offset 0x64, size 0x68
        int stringsOffset = 300;
        string refFiles = @"C:\USERS\DEV\DOWNLOADS\CHEAT.DLL" + "\0" + @"C:\WINDOWS\SYSTEM32\KERNEL32.DLL" + "\0";
        byte[] stringBytes = Encoding.Unicode.GetBytes(refFiles);
        BitConverter.GetBytes(stringsOffset).CopyTo(buffer, 0x64);
        BitConverter.GetBytes(stringBytes.Length).CopyTo(buffer, 0x68);
        stringBytes.CopyTo(buffer, stringsOffset);

        // Timestamps at offset 0x80 (Win10)
        long nowFileTime = DateTime.UtcNow.ToFileTimeUtc();
        BitConverter.GetBytes(nowFileTime).CopyTo(buffer, 0x80);

        // Run count at offset 0xD0
        BitConverter.GetBytes((uint)5).CopyTo(buffer, 0xD0);

        var entry = PrefetchParser.Parse(buffer, "test.pf");

        Assert.Equal("CHEATCLIENT.EXE", entry.ExecutableName);
        Assert.Equal(30u, entry.Version);
        Assert.Equal(5u, entry.RunCount);
        Assert.Single(entry.LastExecutionTimes);
        Assert.Equal(2, entry.ReferencedFiles.Count);
        Assert.Contains(entry.ReferencedFiles, f => f.Contains("CHEAT.DLL"));
        Assert.True(entry.SuspiciousLocation); // Referencing Downloads
    }

    [Fact]
    public void ShimcacheParser_ParsesWin10Entries()
    {
        // Build synthetic "10ts" Shimcache entry
        var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        // "10ts" signature
        bw.Write(Encoding.ASCII.GetBytes("10ts"));
        bw.Write((uint)0); // Unknown
        bw.Write((uint)48); // DataSize

        string testPath = @"C:\Users\Admin\Downloads\autoclicker.exe";
        byte[] pathBytes = Encoding.Unicode.GetBytes(testPath);
        bw.Write((ushort)pathBytes.Length);
        bw.Write(pathBytes);

        // Last modified FILETIME
        long fileTime = DateTime.UtcNow.AddDays(-1).ToFileTimeUtc();
        bw.Write(fileTime);

        // Flags / Executed
        bw.Write((uint)0x02);

        byte[] rawData = ms.ToArray();
        var entries = ShimcacheParser.Parse(rawData);

        Assert.Single(entries);
        Assert.Equal(testPath, entries[0].Path);
        Assert.True(entries[0].Executed);
        Assert.True(entries[0].IsSuspicious);
    }

    [Fact]
    public void BamDamParser_ParsesRegistryValueCorrectly()
    {
        string valueName = @"\Device\HarddiskVolume3\Users\Player\AppData\Local\Temp\vape_loader.exe";
        long execFileTime = DateTime.UtcNow.AddHours(-2).ToFileTimeUtc();

        byte[] valueData = new byte[24];
        BitConverter.GetBytes(execFileTime).CopyTo(valueData, 0);

        var entry = BamDamParser.ParseValue(valueName, valueData, "S-1-5-21-123456-1001", "BAM");

        Assert.NotNull(entry);
        Assert.Equal(valueName, entry!.ExecutablePath);
        Assert.Equal("BAM", entry.SourceService);
        Assert.Equal("S-1-5-21-123456-1001", entry.UserSid);
        Assert.NotNull(entry.LastExecutionUtc);
        Assert.True(entry.IsSuspicious);
    }

    [Fact]
    public void JumpListParser_ParsesSyntheticLnkHeader()
    {
        byte[] lnk = new byte[256];
        // 0x00: Header size 0x4C
        BitConverter.GetBytes(0x4C).CopyTo(lnk, 0);
        // 0x04: CLSID {00021401-0000-0000-C000-000000000046}
        byte[] clsid = new byte[] {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        };
        clsid.CopyTo(lnk, 4);

        // File size at 0x34
        BitConverter.GetBytes(1048576u).CopyTo(lnk, 0x34);

        // Append ASCII path at offset 76
        string fakePath = @"C:\Users\Target\Downloads\cheat_injector.exe" + "\0";
        Encoding.ASCII.GetBytes(fakePath).CopyTo(lnk, 76);

        var list = JumpListParser.ParseStreamOrFile(lnk, "automaticDestinations-ms");
        Assert.NotEmpty(list);
        Assert.Contains(list, x => x.TargetPath.Contains("cheat_injector.exe"));
        Assert.True(list[0].IsSuspicious);
    }
}

