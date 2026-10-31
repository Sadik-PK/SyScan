using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SyScan.Scanner.FileSystem;

public record PeSection(string Name, uint VirtualSize, uint VirtualAddress, uint SizeOfRawData, uint Characteristics);

public record PeMetadata(
    bool IsValidPe,
    string MachineType,
    DateTime? CompileTime,
    bool Is64Bit,
    bool IsDll,
    string Subsystem,
    uint EntryPoint,
    bool IsDotNet,
    string? ExportedName,
    IReadOnlyList<PeSection> Sections
);

/// <summary>
/// Managed, read-only Portable Executable (PE32 / PE32+) parser.
/// Safely extracts machine type, compile timestamp, sections, and CLR metadata without external dependencies.
/// </summary>
public static class PeHeaderParser
{
    private const ushort DosMagic = 0x5A4D; // "MZ"
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;

    public static PeMetadata Parse(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Parse(fs);
        }
        catch
        {
            return CreateInvalid();
        }
    }

    public static PeMetadata Parse(Stream stream)
    {
        try
        {
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

            if (stream.Length < 64)
                return CreateInvalid();

            // 1. DOS Header
            ushort magic = reader.ReadUInt16();
            if (magic != DosMagic)
                return CreateInvalid();

            stream.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = reader.ReadInt32();

            if (peOffset <= 0 || peOffset + 4 >= stream.Length)
                return CreateInvalid();

            // 2. PE Signature
            stream.Seek(peOffset, SeekOrigin.Begin);
            uint sig = reader.ReadUInt32();
            if (sig != PeSignature)
                return CreateInvalid();

            // 3. COFF File Header
            ushort machine = reader.ReadUInt16();
            ushort numberOfSections = reader.ReadUInt16();
            uint timeDateStamp = reader.ReadUInt32();
            reader.ReadUInt32(); // PointerToSymbolTable
            reader.ReadUInt32(); // NumberOfSymbols
            ushort sizeOfOptionalHeader = reader.ReadUInt16();
            ushort characteristics = reader.ReadUInt16();

            bool isDll = (characteristics & 0x2000) != 0;
            DateTime? compileTime = null;
            if (timeDateStamp > 0 && timeDateStamp < 2500000000)
            {
                compileTime = DateTime.UnixEpoch.AddSeconds(timeDateStamp);
            }

            string machineType = machine switch
            {
                0x014C => "i386 (32-bit)",
                0x8664 => "AMD64 (64-bit)",
                0xAA64 => "ARM64",
                0x0200 => "IA64",
                _ => $"0x{machine:X4}"
            };

            // 4. Optional Header
            bool is64Bit = false;
            string subsystem = "Unknown";
            uint entryPoint = 0;
            bool isDotNet = false;
            string? exportedName = null;

            if (sizeOfOptionalHeader > 0)
            {
                long optHeaderPos = stream.Position;
                ushort optMagic = reader.ReadUInt16();
                is64Bit = optMagic == Pe32PlusMagic;

                reader.ReadByte(); // MajorLinkerVersion
                reader.ReadByte(); // MinorLinkerVersion
                reader.ReadUInt32(); // SizeOfCode
                reader.ReadUInt32(); // SizeOfInitializedData
                reader.ReadUInt32(); // SizeOfUninitializedData
                entryPoint = reader.ReadUInt32(); // AddressOfEntryPoint

                // Skip to Subsystem
                // In PE32: Subsystem is at offset 68 from optHeaderPos
                // In PE32+: Subsystem is at offset 68 as well
                stream.Seek(optHeaderPos + 68, SeekOrigin.Begin);
                ushort subsysCode = reader.ReadUInt16();
                subsystem = subsysCode switch
                {
                    1 => "Native",
                    2 => "Windows GUI",
                    3 => "Windows Console",
                    7 => "POSIX",
                    9 => "Windows CE",
                    10 => "EFI Application",
                    _ => $"Subsystem-{subsysCode}"
                };

                // Data Directories:
                // PE32: offset 96
                // PE32+: offset 112
                int dataDirOffset = is64Bit ? 112 : 96;
                if (sizeOfOptionalHeader >= dataDirOffset + 128)
                {
                    stream.Seek(optHeaderPos + dataDirOffset, SeekOrigin.Begin);
                    uint exportTableRva = reader.ReadUInt32();
                    reader.ReadUInt32(); // export size

                    // Skip import, resource, exception, certificate, basereloc, debug, architecture, globalptr, tls, loadconfig, boundimport, iat, delayimport
                    // CLR Runtime Header is Data Directory index 14 (14 * 8 = 112 bytes from start of data dirs)
                    stream.Seek(optHeaderPos + dataDirOffset + (14 * 8), SeekOrigin.Begin);
                    uint clrRva = reader.ReadUInt32();
                    isDotNet = clrRva != 0;
                }

                // Seek past optional header to sections
                stream.Seek(optHeaderPos + sizeOfOptionalHeader, SeekOrigin.Begin);
            }

            // 5. Section Headers
            var sections = new List<PeSection>();
            for (int i = 0; i < Math.Min((int)numberOfSections, 96); i++)
            {
                byte[] nameBytes = reader.ReadBytes(8);
                string secName = Encoding.UTF8.GetString(nameBytes).TrimEnd('\0');
                uint virtSize = reader.ReadUInt32();
                uint virtAddr = reader.ReadUInt32();
                uint rawSize = reader.ReadUInt32();
                reader.ReadUInt32(); // raw address
                reader.ReadUInt32(); // relocations
                reader.ReadUInt32(); // linenumbers
                reader.ReadUInt16(); // num reloc
                reader.ReadUInt16(); // num linenum
                uint sectionCharacteristics = reader.ReadUInt32();

                sections.Add(new PeSection(secName, virtSize, virtAddr, rawSize, sectionCharacteristics));
            }

            return new PeMetadata(
                IsValidPe: true,
                MachineType: machineType,
                CompileTime: compileTime,
                Is64Bit: is64Bit,
                IsDll: isDll,
                Subsystem: subsystem,
                EntryPoint: entryPoint,
                IsDotNet: isDotNet,
                ExportedName: exportedName,
                Sections: sections
            );
        }
        catch
        {
            return CreateInvalid();
        }
    }

    private static PeMetadata CreateInvalid() => new(
        IsValidPe: false,
        MachineType: "Not a valid PE",
        CompileTime: null,
        Is64Bit: false,
        IsDll: false,
        Subsystem: "None",
        EntryPoint: 0,
        IsDotNet: false,
        ExportedName: null,
        Sections: Array.Empty<PeSection>()
    );
}

