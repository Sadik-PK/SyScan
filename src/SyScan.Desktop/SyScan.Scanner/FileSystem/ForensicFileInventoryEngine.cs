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
    string ActualFileType = "Executable",
    JarAnalysisResult? JarInfo = null,
    string DiscoverySource = "DriveScan",
    string? AssociatedGame = null,
    string FileAnalysisStatus = "Analyzed", // "Analyzed", "Inaccessible", "TooLarge", "Locked"
    string DetectionStatus = "Clean",     // "Clean", "CheatUtility", "Suspicious", "UnderReview"
    string DiscoveryContext = "Found on disk",
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
        ".exe", ".jar", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".bat", ".cmd", ".ps1", ".vbs", ".js"
    };

    public HashSet<string> ExcludedDirectoryNames { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "winsxs", "$recycle.bin", "system volume information", "node_modules", "assembly",
        "softwaredistribution", ".git", "packages", "nuget"
    };

    public int MaxFilesToScan { get; set; } = 15000;
    public int MaxDirectoryDepth { get; set; } = 12;
    public bool ComputeHashForLargeFiles { get; set; } = true;
    public long MaxHashSizeBytes { get; set; } = 250 * 1024 * 1024; // 250 MB
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

    /// <summary>
    /// Dynamically discovers all scan roots across all ready fixed local drives.
    /// Does not assume Windows is on C:.
    /// </summary>
    public static List<string> DiscoverScanRoots(IEnumerable<string>? customRoots = null)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (customRoots != null)
        {
            foreach (var r in customRoots.Where(Directory.Exists))
                roots.Add(r);
        }

        // Dynamically find all ready local fixed drives
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                    continue;

                string dRoot = drive.RootDirectory.FullName;

                // 1. Users directory on this drive
                string usersPath = Path.Combine(dRoot, "Users");
                if (Directory.Exists(usersPath))
                {
                    try
                    {
                        foreach (var userDir in Directory.GetDirectories(usersPath))
                        {
                            string uName = Path.GetFileName(userDir);
                            if (uName is "Public" or "Default" or "All Users" or "Default User") continue;

                            AddIfExists(roots, Path.Combine(userDir, "Downloads"));
                            AddIfExists(roots, Path.Combine(userDir, "Desktop"));
                            AddIfExists(roots, Path.Combine(userDir, "Documents"));
                            AddIfExists(roots, Path.Combine(userDir, "AppData", "Local", "Temp"));
                            AddIfExists(roots, Path.Combine(userDir, "AppData", "Roaming", ".minecraft"));
                            AddIfExists(roots, Path.Combine(userDir, "AppData", "Roaming", "PrismLauncher"));
                            AddIfExists(roots, Path.Combine(userDir, "AppData", "Local", "Programs"));
                            AddIfExists(roots, Path.Combine(userDir, ".lunarclient"));
                            AddIfExists(roots, Path.Combine(userDir, ".feather"));
                        }
                    }
                    catch { }
                }

                // 2. Program Files and ProgramData on this drive
                AddIfExists(roots, Path.Combine(dRoot, "Program Files"));
                AddIfExists(roots, Path.Combine(dRoot, "Program Files (x86)"));
                AddIfExists(roots, Path.Combine(dRoot, "ProgramData"));
                AddIfExists(roots, Path.Combine(dRoot, "Games"));
                AddIfExists(roots, Path.Combine(dRoot, "XboxGames"));
            }
        }
        catch { }

        // Fallbacks
        AddIfExists(roots, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        AddIfExists(roots, Path.GetTempPath());

        return roots.ToList();
    }

    private static void AddIfExists(HashSet<string> set, string path)
    {
        if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            set.Add(path);
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

                // Check digital signature & metadata based on format
                DigitalSignatureInfo sigInfo = new(false, null, null, null, null, null, false);
                PeMetadata? peMetadata = null;
                JarAnalysisResult? jarInfo = null;

                string actualFileType = ClassifyFileType(ext);
                string discoverySource = ClassifySource(fullPath);
                string discoveryContext = ClassifyContext(fullPath);
                string? associatedGame = null;
                string detectionStatus = "Clean";
                string? detectionNote = null;

                // SPECIAL JAR HANDLING
                if (ext.Equals(".jar", StringComparison.OrdinalIgnoreCase))
                {
                    actualFileType = "JAR";
                    jarInfo = JarAnalyzer.AnalyzeJar(fullPath);

                    if (jarInfo.IsKnownCheatClient)
                    {
                        detectionStatus = "CheatUtility";
                        associatedGame = "minecraft";
                        detectionNote = jarInfo.DetectionReason;
                    }
                    else if (jarInfo.MinecraftMod != null)
                    {
                        associatedGame = "minecraft";
                        detectionNote = $"Minecraft Mod: {jarInfo.MinecraftMod.DisplayName} (v{jarInfo.MinecraftMod.Version}, {jarInfo.MinecraftMod.LoaderType})";
                    }
                    else if (fullPath.Contains(".minecraft", StringComparison.OrdinalIgnoreCase))
                    {
                        associatedGame = "minecraft";
                    }

                    // Map JAR signature to digital signature info
                    if (jarInfo.IsJarSigned)
                    {
                        sigInfo = new DigitalSignatureInfo(
                            IsSigned: true,
                            Subject: jarInfo.JarSignerCertificate ?? "JAR Certificate",
                            Issuer: "Java Code Signing Authority",
                            Thumbprint: null,
                            ValidFrom: null,
                            ValidTo: null,
                            IsTrustedVendor: false
                        );
                    }
                }
                else if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                         ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                         ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                         ext.Equals(".scr", StringComparison.OrdinalIgnoreCase))
                {
                    sigInfo = AuthenticodeVerifier.Verify(fullPath);
                    peMetadata = PeHeaderParser.Parse(fullPath);
                    actualFileType = ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
                        ? "Driver"
                        : (peMetadata != null ? (peMetadata.Is64Bit ? "PE32+" : "PE32") : "Executable");

                    // Associate games if located in known directories
                    if (fullPath.Contains("FiveM", StringComparison.OrdinalIgnoreCase) || fullPath.Contains("CitizenFX", StringComparison.OrdinalIgnoreCase))
                        associatedGame = "fivem";
                    else if (fullPath.Contains("Roblox", StringComparison.OrdinalIgnoreCase))
                        associatedGame = "roblox";
                    else if (fullPath.Contains("Rainbow Six", StringComparison.OrdinalIgnoreCase) || fullPath.Contains("Siege", StringComparison.OrdinalIgnoreCase))
                        associatedGame = "r6siege";
                    else if (fullPath.Contains(".minecraft", StringComparison.OrdinalIgnoreCase))
                        associatedGame = "minecraft";
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
                    IsSuspiciousPath: isSuspiciousPath,
                    ActualFileType: actualFileType,
                    JarInfo: jarInfo,
                    DiscoverySource: discoverySource,
                    AssociatedGame: associatedGame,
                    FileAnalysisStatus: "Analyzed",
                    DetectionStatus: detectionStatus,
                    DiscoveryContext: discoveryContext,
                    DetectionNote: detectionNote
                );

                results.Add(record);
            }
            catch (UnauthorizedAccessException)
            {
                // Record file as Inaccessible so coverage is transparent
                results.Add(new ForensicFileRecord(
                    FullPath: file.FullName,
                    FileName: file.Name,
                    Extension: ext,
                    FileSizeBytes: 0,
                    CreationTimeUtc: DateTime.MinValue,
                    LastWriteTimeUtc: DateTime.MinValue,
                    LastAccessTimeUtc: DateTime.MinValue,
                    Sha256Hash: "inaccessible",
                    Signature: new DigitalSignatureInfo(false, null, null, null, null, null, false),
                    PeInfo: null,
                    IsSuspiciousPath: false,
                    ActualFileType: ClassifyFileType(ext),
                    FileAnalysisStatus: "Inaccessible",
                    DetectionStatus: "UnderReview",
                    DiscoveryContext: "Permission Denied by OS",
                    DetectionNote: "Access denied: file could not be read without higher privileges"
                ));
            }
            catch (IOException)
            {
                // File locked by process
                results.Add(new ForensicFileRecord(
                    FullPath: file.FullName,
                    FileName: file.Name,
                    Extension: ext,
                    FileSizeBytes: 0,
                    CreationTimeUtc: DateTime.MinValue,
                    LastWriteTimeUtc: DateTime.MinValue,
                    LastAccessTimeUtc: DateTime.MinValue,
                    Sha256Hash: "locked",
                    Signature: new DigitalSignatureInfo(false, null, null, null, null, null, false),
                    PeInfo: null,
                    IsSuspiciousPath: false,
                    ActualFileType: ClassifyFileType(ext),
                    FileAnalysisStatus: "Locked",
                    DetectionStatus: "UnderReview",
                    DiscoveryContext: "File locked by running process",
                    DetectionNote: "File is exclusively locked by another process"
                ));
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

    private static string ClassifyFileType(string ext) => ext.ToLowerInvariant() switch
    {
        ".exe" => "Executable",
        ".jar" => "JAR",
        ".dll" => "DynamicLinkLibrary",
        ".sys" => "Driver",
        ".scr" => "ScreensaverBinary",
        ".com" => "MSDOSBinary",
        ".ocx" => "ActiveXControl",
        ".cpl" => "ControlPanelBinary",
        ".bat" or ".cmd" => "BatchScript",
        ".ps1" => "PowerShellScript",
        ".vbs" => "VBScript",
        ".js" => "JavaScript",
        _ => "Binary"
    };

    private static string ClassifySource(string fullPath)
    {
        string lower = fullPath.ToLowerInvariant();
        if (lower.Contains(@"\downloads\")) return "Downloads";
        if (lower.Contains(@"\desktop\")) return "Desktop";
        if (lower.Contains(@"\.minecraft\mods")) return "MinecraftMods";
        if (lower.Contains(@"\appdata\local\temp\") || lower.Contains(@"\windows\temp\")) return "Temp";
        if (lower.Contains(@"\appdata\")) return "AppData";
        if (lower.Contains(@"\program files")) return "ProgramFiles";
        return "DriveScan";
    }

    private static string ClassifyContext(string fullPath)
    {
        string lower = fullPath.ToLowerInvariant();
        if (lower.Contains(@"\downloads\")) return "Found on disk (in Downloads directory)";
        if (lower.Contains(@"\desktop\")) return "Found on disk (in Desktop directory)";
        if (lower.Contains(@"\.minecraft\mods") || lower.Contains(@"\mods\")) return "Installed in game mod directory";
        if (lower.Contains(@"\temp\")) return "Located in volatile temporary directory";
        return "Discovered on local drive volume";
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
