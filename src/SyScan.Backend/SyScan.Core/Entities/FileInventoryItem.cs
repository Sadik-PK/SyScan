using System;

namespace SyScan.Core.Entities;

public class FileInventoryItem : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    public string FileId { get; set; } = string.Empty; // e.g. FIL-0001
    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public string Extension { get; set; } = string.Empty;
    public string ActualFileType { get; set; } = "Executable"; // PE32, PE32+, JAR, Driver, BatchScript, etc.
    public long FileSizeBytes { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public DateTime CreationTimeUtc { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
    public DateTime? LastAccessTimeUtc { get; set; }

    public string DigitalSignatureState { get; set; } = "Unsigned"; // SignedVerified, Unsigned, InvalidSignature, JarSigned, JarUnsigned
    public string? Publisher { get; set; }
    public string? ProductName { get; set; }
    public string? ProductVersion { get; set; }

    public string? PeMetadataJson { get; set; }
    public string? JarMetadataJson { get; set; }

    public string DiscoverySource { get; set; } = "DriveScan"; // Downloads, Desktop, MinecraftMods, DriveScan
    public string? AssociatedGame { get; set; } // minecraft, fivem, roblox, r6siege
    public string FileAnalysisStatus { get; set; } = "Analyzed"; // Analyzed, Inaccessible, TooLarge, Locked
    public string DetectionStatus { get; set; } = "Clean"; // Clean, Suspicious, CheatUtility, UnderReview
    public string DiscoveryContext { get; set; } = "Found on disk";
    public string? DetectionNotes { get; set; }
}
