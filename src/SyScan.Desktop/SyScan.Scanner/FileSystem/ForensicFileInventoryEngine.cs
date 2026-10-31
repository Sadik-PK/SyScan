using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.FileSystem;

public record ForensicFileRecord(
    string FullPath,
    string FileName,
    string Extension,
    long FileSizeBytes,
    DateTime CreationTimeUtc,
    DateTime LastWriteTimeUtc,
    DateTime LastAccessTimeUtc,
    string Sha256Hash,
    DigitalSignatureInfo Signature,
    PeMetadata? PeInfo,
    bool IsSuspiciousPath,
    string? DetectionNote = null
);

public record FileScanProgress(
    string CurrentDirectory,
    int FilesScanned,
    int RelevantFilesFound,
    int DetectionsFound
);

public class ForensicFileInventoryOptions
{
    public HashSet<string> TargetExtensions { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".zip", ".7z", ".rar"
    };

    public HashSet<string> ExcludedDirectoryNames { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "winsxs", "$recycle.bin", "system volume information", "node_modules", "assembly",
        "softwaredistribution", ".git", "packages", "nuget"
    };

    public int MaxFilesToScan { get; set; } = 8000;
    public int MaxDirectoryDepth { get; set; } = 12;
    public bool ComputeHashForLargeFiles { get; set; } = true;
    public long MaxHashSizeBytes { get; set; } = 150 * 1024 * 1024; // 150 MB
}

public class ForensicFileInventoryEngine
{
    private readonly ForensicFileInventoryOptions _options;

    public ForensicFileInventoryEngine(ForensicFileInventoryOptions? options = null)
    {
        _options = options ?? new ForensicFileInventoryOptions();
    }

    private class ScanCounter
    {
        public int TotalFilesInspected;
    }

    public async Task<IReadOnlyList<ForensicFileRecord>> ScanDirectoriesAsync(
        IEnumerable<string> rootDirectories,
        IProgress<FileScanProgress>? progress,
        CancellationToken ct)
    {
        var results = new List<ForensicFileRecord>();
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var counter = new ScanCounter();

        foreach (var root in rootDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            await TraverseDirectoryAsync(
                new DirectoryInfo(root),
                0,
                results,
                seenHashes,
                counter,
                progress,
                ct
            );

            if (results.Count >= _options.MaxFilesToScan) break;
        }

        return results;
    }

    private async Task TraverseDirectoryAsync(
        DirectoryInfo dir,
        int currentDepth,
        List<ForensicFileRecord> results,
        HashSet<string> seenHashes,
        ScanCounter counter,
        IProgress<FileScanProgress>? progress,
        CancellationToken ct)
    {
        if (currentDepth > _options.MaxDirectoryDepth || results.Count >= _options.MaxFilesToScan)
            return;

        // Skip symlinks, junctions, and reparse points to prevent infinite recursion
        if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
            return;

        // Check excluded directory names
        if (_options.ExcludedDirectoryNames.Contains(dir.Name))
            return;

        FileInfo[] files;
        try
        {
            files = dir.GetFiles();
        }
        catch (UnauthorizedAccessException)
        {
            return; // Normal in Windows security boundary
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }
        catch (Exception)
        {
            return;
        }

        progress?.Report(new FileScanProgress(dir.FullName, counter.TotalFilesInspected, results.Count, 0));

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            if (results.Count >= _options.MaxFilesToScan) break;

            counter.TotalFilesInspected++;
            string ext = file.Extension;

            if (!_options.TargetExtensions.Contains(ext))
                continue;

            try
            {
                // Skip reparse points for files as well
                if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                    continue;

                string fullPath = file.FullName;
                long size = file.Length;

                // Compute SHA-256 streaming
                string sha256 = "hash_unavailable";
                if (size <= _options.MaxHashSizeBytes)
                {
                    sha256 = await ComputeSha256Async(fullPath, ct);
                }

                // Check digital signature for binary executables
                DigitalSignatureInfo sigInfo = new(false, null, null, null, null, null, false);
                PeMetadata? peMetadata = null;

                if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".scr", StringComparison.OrdinalIgnoreCase))
                {
                    sigInfo = AuthenticodeVerifier.Verify(fullPath);
                    peMetadata = PeHeaderParser.Parse(fullPath);
                }

                bool isSuspiciousPath = IsSuspiciousExecutionPath(fullPath);

                var record = new ForensicFileRecord(
                    FullPath: fullPath,
                    FileName: file.Name,
                    Extension: ext,
                    FileSizeBytes: size,
                    CreationTimeUtc: file.CreationTimeUtc,
                    LastWriteTimeUtc: file.LastWriteTimeUtc,
                    LastAccessTimeUtc: file.LastAccessTimeUtc,
                    Sha256Hash: sha256,
                    Signature: sigInfo,
                    PeInfo: peMetadata,
                    IsSuspiciousPath: isSuspiciousPath
                );

                results.Add(record);
            }
            catch (UnauthorizedAccessException)
            {
                // Graceful skip
            }
            catch (IOException)
            {
                // File locked by process, continue
            }
        }

        // Recurse subdirectories
        DirectoryInfo[] subDirs;
        try
        {
            subDirs = dir.GetDirectories();
        }
        catch
        {
            return;
        }

        foreach (var subDir in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await TraverseDirectoryAsync(
                subDir,
                currentDepth + 1,
                results,
                seenHashes,
                counter,
                progress,
                ct
            );
        }
    }

    public static bool IsSuspiciousExecutionPath(string fullPath)
    {
        var lower = fullPath.ToLowerInvariant();
        return lower.Contains(@"\appdata\local\temp\") ||
               lower.Contains(@"\windows\temp\") ||
               lower.Contains(@"\appdata\roaming\microsoft\windows\start menu\programs\startup\") ||
               lower.Contains(@"\downloads\");
    }

    private static async Task<string> ComputeSha256Async(string filePath, CancellationToken ct)
    {
        try
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, useAsync: true);
            var hashBytes = await sha.ComputeHashAsync(stream, ct);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
        catch
        {
            return "hash_unavailable";
        }
    }
}
