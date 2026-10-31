using System;
using System.IO;
using System.Text;
using SyScan.Scanner.FileSystem;
using Xunit;

namespace SyScan.Tests;

public class PeHeaderParserTests
{
    [Fact]
    public void Parse_InvalidData_ReturnsInvalidPe()
    {
        using var ms = new MemoryStream(new byte[] { 0x00, 0x01, 0x02, 0x03 });
        var metadata = PeHeaderParser.Parse(ms);
        Assert.False(metadata.IsValidPe);
    }

    [Fact]
    public void Parse_SyntheticPe32Header_ExtractsMetadataCorrectly()
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        // 1. DOS Header
        writer.Write((ushort)0x5A4D); // "MZ"
        ms.Seek(0x3C, SeekOrigin.Begin);
        writer.Write((int)0x80); // e_lfanew = 128

        // 2. PE Header at 0x80
        ms.Seek(0x80, SeekOrigin.Begin);
        writer.Write((uint)0x00004550); // "PE\0\0"

        // COFF File Header
        writer.Write((ushort)0x8664); // AMD64
        writer.Write((ushort)2); // 2 sections
        writer.Write((uint)1700000000); // TimeDateStamp
        writer.Write((uint)0); // PointerToSymbolTable
        writer.Write((uint)0); // NumberOfSymbols
        writer.Write((ushort)240); // SizeOfOptionalHeader
        writer.Write((ushort)0x0002); // Executable

        // Optional Header (PE32+)
        long optHeaderPos = ms.Position;
        writer.Write((ushort)0x20B); // PE32+
        writer.Write((byte)14); // MajorLinkerVersion
        writer.Write((byte)0); // MinorLinkerVersion
        writer.Write((uint)1024); // SizeOfCode
        writer.Write((uint)512); // SizeOfInitializedData
        writer.Write((uint)0); // SizeOfUninitializedData
        writer.Write((uint)0x1000); // EntryPoint

        // Write Subsystem at optHeaderPos + 68
        ms.Seek(optHeaderPos + 68, SeekOrigin.Begin);
        writer.Write((ushort)3); // Windows Console

        // Move to sections at optHeaderPos + 240
        ms.Seek(optHeaderPos + 240, SeekOrigin.Begin);

        // Section 1: .text
        writer.Write(Encoding.UTF8.GetBytes(".text\0\0\0"));
        writer.Write((uint)0x1000); // VirtualSize
        writer.Write((uint)0x1000); // VirtualAddress
        writer.Write((uint)0x1000); // SizeOfRawData
        writer.Write((uint)0x400); // PointerToRawData
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((uint)0x60000020); // Characteristics

        // Section 2: .data
        writer.Write(Encoding.UTF8.GetBytes(".data\0\0\0"));
        writer.Write((uint)0x500); // VirtualSize
        writer.Write((uint)0x2000); // VirtualAddress
        writer.Write((uint)0x600); // SizeOfRawData
        writer.Write((uint)0x1400); // PointerToRawData
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((uint)0xC0000040); // Characteristics

        ms.Seek(0, SeekOrigin.Begin);

        var result = PeHeaderParser.Parse(ms);

        Assert.True(result.IsValidPe);
        Assert.True(result.Is64Bit);
        Assert.Equal("AMD64 (64-bit)", result.MachineType);
        Assert.Equal("Windows Console", result.Subsystem);
        Assert.Equal((uint)0x1000, result.EntryPoint);
        Assert.Equal(2, result.Sections.Count);
        Assert.Equal(".text", result.Sections[0].Name);
        Assert.Equal(".data", result.Sections[1].Name);
    }

    [Fact]
    public void Parse_RealSystemBinary_ExtractsValidPeInfo()
    {
        string kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "kernel32.dll");
        if (!File.Exists(kernel32)) return; // Environment check

        var metadata = PeHeaderParser.Parse(kernel32);

        Assert.True(metadata.IsValidPe);
        Assert.True(metadata.Is64Bit || metadata.MachineType.Contains("32-bit"));
        Assert.True(metadata.IsDll);
        Assert.NotEmpty(metadata.Sections);
        Assert.Contains(metadata.Sections, s => s.Name.StartsWith(".text"));
    }

    [Fact]
    public void AuthenticodeVerifier_RealSystemBinary_VerifiesMicrosoftSignature()
    {
        string kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "kernel32.dll");
        if (!File.Exists(kernel32)) return;

        var sig = AuthenticodeVerifier.Verify(kernel32);

        Assert.True(sig.IsSigned);
        Assert.NotNull(sig.Subject);
        Assert.Contains("Microsoft", sig.Subject);
        Assert.True(sig.IsTrustedVendor);
    }
}

