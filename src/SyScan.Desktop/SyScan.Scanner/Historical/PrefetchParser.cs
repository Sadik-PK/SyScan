using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SyScan.Scanner.Historical;

public sealed class PrefetchEntry
{
    public string SourceFilePath { get; set; } = string.Empty;
    public string ExecutableName { get; set; } = string.Empty;
    public uint Version { get; set; }
    public uint RunCount { get; set; }
    public uint PrefetchHash { get; set; }
    public List<DateTime> LastExecutionTimes { get; set; } = new();
    public List<string> ReferencedFiles { get; set; } = new();
    public List<string> Volumes { get; set; } = new();
    public bool IsCompressed { get; set; }
    public bool SuspiciousLocation { get; set; }
    public List<string> SuspiciousReferencedFiles { get; set; } = new();
}

public static class PrefetchParser
{
    private const uint MAM_SIGNATURE = 0x044D414D; // "MAM\x04"
    private const uint SCCA_SIGNATURE = 0x41434353; // "SCCA"
    private const ushort COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004;

    [DllImport("ntdll.dll")]
    private static extern int RtlGetCompressionWorkSpaceSize(
        ushort formatAndEngine,
        out uint compressBufferWorkSpaceSize,
        out uint compressFragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBufferEx(
        ushort compressionFormat,
        byte[] uncompressedBuffer,
        int uncompressedBufferSize,
        byte[] compressedBuffer,
        int compressedBufferSize,
        out int finalUncompressedSize,
        byte[] workSpace);

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBuffer(
        ushort compressionFormat,
        byte[] uncompressedBuffer,
        int uncompressedBufferSize,
        byte[] compressedBuffer,
        int compressedBufferSize,
        out int finalUncompressedSize);

    public static byte[] DecompressMam(byte[] rawBytes)
    {
        if (rawBytes.Length < 8)
            throw new InvalidDataException("Buffer too small for MAM header.");

        uint magic = BitConverter.ToUInt32(rawBytes, 0);
        if (magic != MAM_SIGNATURE)
        {
            return rawBytes; // Already uncompressed or not MAM
        }

        int uncompressedSize = BitConverter.ToInt32(rawBytes, 4);
        if (uncompressedSize <= 0 || uncompressedSize > 100 * 1024 * 1024) // 100MB sanity guard
            throw new InvalidDataException($"Invalid uncompressed size: {uncompressedSize}");

        byte[] uncompressedBuffer = new byte[uncompressedSize];
        byte[] compressedPayload = new byte[rawBytes.Length - 8];
        Buffer.BlockCopy(rawBytes, 8, compressedPayload, 0, compressedPayload.Length);

        // Try RtlDecompressBufferEx with workspace
        try
        {
            int status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF, out uint workspaceSize, out _);
            if (status == 0 && workspaceSize > 0 && workspaceSize < 10 * 1024 * 1024)
            {
                byte[] workspace = new byte[workspaceSize];
                status = RtlDecompressBufferEx(
                    COMPRESSION_FORMAT_XPRESS_HUFF,
                    uncompressedBuffer,
                    uncompressedSize,
                    compressedPayload,
                    compressedPayload.Length,
                    out int finalSize,
                    workspace);

                if (status == 0)
                {
                    if (finalSize != uncompressedSize)
                    {
                        Array.Resize(ref uncompressedBuffer, finalSize);
                    }
                    return uncompressedBuffer;
                }
            }
        }
        catch
        {
            // Fallback to RtlDecompressBuffer
        }

        // Fallback to standard RtlDecompressBuffer
        int fallbackStatus = RtlDecompressBuffer(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            uncompressedBuffer,
            uncompressedSize,
            compressedPayload,
            compressedPayload.Length,
            out int standardFinalSize);

        if (fallbackStatus != 0)
            throw new InvalidOperationException($"Decompression failed with NTSTATUS 0x{fallbackStatus:X8}");

        if (standardFinalSize != uncompressedSize)
        {
            Array.Resize(ref uncompressedBuffer, standardFinalSize);
        }

        return uncompressedBuffer;
    }

    public static PrefetchEntry Parse(byte[] data, string sourcePath = "")
    {
        bool wasCompressed = false;
        if (data.Length >= 4 && BitConverter.ToUInt32(data, 0) == MAM_SIGNATURE)
        {
            data = DecompressMam(data);
            wasCompressed = true;
        }

        if (data.Length < 84)
            throw new InvalidDataException("Invalid Prefetch file: buffer too small.");

        uint version = BitConverter.ToUInt32(data, 0);
        uint magic = BitConverter.ToUInt32(data, 4);

        if (magic != SCCA_SIGNATURE)
            throw new InvalidDataException($"Invalid Prefetch signature: 0x{magic:X8}, expected SCCA (0x41434353)");

        var entry = new PrefetchEntry
        {
            SourceFilePath = sourcePath,
            Version = version,
            IsCompressed = wasCompressed
        };

        // Executable name (offset 0x10, 60 bytes UTF-16LE)
        string exeName = Encoding.Unicode.GetString(data, 0x10, 60);
        int nullIdx = exeName.IndexOf('\0');
        entry.ExecutableName = nullIdx >= 0 ? exeName.Substring(0, nullIdx).Trim() : exeName.Trim();

        // Hash (offset 0x4C)
        if (data.Length >= 0x50)
        {
            entry.PrefetchHash = BitConverter.ToUInt32(data, 0x4C);
        }

        // Run count & Timestamps based on version
        if (version == 23) // Windows 7
        {
            if (data.Length >= 0x9C)
            {
                entry.RunCount = BitConverter.ToUInt32(data, 0x98);
                long fileTime = BitConverter.ToInt64(data, 0x78);
                if (fileTime > 0)
                {
                    try { entry.LastExecutionTimes.Add(DateTime.FromFileTimeUtc(fileTime)); } catch { }
                }
            }
        }
        else if (version == 26 || version == 30 || version == 31) // Win 8, 8.1, 10, 11
        {
            if (data.Length >= 0xD4)
            {
                entry.RunCount = BitConverter.ToUInt32(data, 0xD0);

                // Up to 8 FILETIMEs at offset 0x80
                for (int i = 0; i < 8; i++)
                {
                    int offset = 0x80 + (i * 8);
                    if (offset + 8 <= data.Length)
                    {
                        long fileTime = BitConverter.ToInt64(data, offset);
                        if (fileTime > 0)
                        {
                            try
                            {
                                entry.LastExecutionTimes.Add(DateTime.FromFileTimeUtc(fileTime));
                            }
                            catch { }
                        }
                    }
                }
            }
        }

        // Section C: Referenced Files Strings
        // Win 10/11: Offset 0x64 (uint32 offset), Offset 0x68 (uint32 size)
        // Win 7: Offset 0x64 (uint32 offset), Offset 0x68 (uint32 size)
        if (data.Length >= 0x6C)
        {
            int stringsOffset = BitConverter.ToInt32(data, 0x64);
            int stringsSize = BitConverter.ToInt32(data, 0x68);

            if (stringsOffset > 0 && stringsSize > 0 && stringsOffset + stringsSize <= data.Length)
            {
                string rawStrings = Encoding.Unicode.GetString(data, stringsOffset, stringsSize);
                string[] parts = rawStrings.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                foreach (string part in parts)
                {
                    string trimmed = part.Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        entry.ReferencedFiles.Add(trimmed);

                        // Suspicious indicators: running from temp, loading suspicious dlls, or cheat injectors
                        string lower = trimmed.ToLowerInvariant();
                        if (lower.Contains(@"\appdata\local\temp\") ||
                            lower.Contains(@"\downloads\") ||
                            lower.EndsWith(".tmp") ||
                            lower.Contains("inject") ||
                            lower.Contains("hook") ||
                            lower.Contains("cheat") ||
                            lower.Contains("bypass"))
                        {
                            entry.SuspiciousReferencedFiles.Add(trimmed);
                        }
                    }
                }
            }
        }

        // Section D: Volumes
        if (data.Length >= 0x78)
        {
            int volumeOffset = BitConverter.ToInt32(data, 0x6C);
            int volumeCount = BitConverter.ToInt32(data, 0x70);
            int volumeSize = BitConverter.ToInt32(data, 0x74);

            if (volumeOffset > 0 && volumeSize > 0 && volumeOffset + volumeSize <= data.Length && volumeCount > 0)
            {
                // Extract volume path strings if present in volume entry
                int currentVolOffset = volumeOffset;
                for (int v = 0; v < volumeCount && currentVolOffset + 16 <= data.Length; v++)
                {
                    int devPathOffset = BitConverter.ToInt32(data, currentVolOffset);
                    int devPathLength = BitConverter.ToInt32(data, currentVolOffset + 4);

                    if (devPathOffset > 0 && devPathLength > 0 && volumeOffset + devPathOffset + (devPathLength * 2) <= data.Length)
                    {
                        string volDevPath = Encoding.Unicode.GetString(data, volumeOffset + devPathOffset, devPathLength * 2).TrimEnd('\0');
                        entry.Volumes.Add(volDevPath);
                    }
                    currentVolOffset += 96; // typical volume entry size in Win10/11
                }
            }
        }

        if (entry.SuspiciousReferencedFiles.Count > 0)
        {
            entry.SuspiciousLocation = true;
        }

        return entry;
    }

    public static IEnumerable<PrefetchEntry> ScanDirectory(string prefetchDirectory = @"C:\Windows\Prefetch")
    {
        if (!Directory.Exists(prefetchDirectory))
            yield break;

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(prefetchDirectory, "*.pf");
        }
        catch
        {
            yield break;
        }

        foreach (string file in pfFiles)
        {
            PrefetchEntry? entry = null;
            try
            {
                byte[] raw = File.ReadAllBytes(file);
                entry = Parse(raw, file);
            }
            catch
            {
                // Inaccessible or unsupported version
            }

            if (entry != null)
                yield return entry;
        }
    }
}

