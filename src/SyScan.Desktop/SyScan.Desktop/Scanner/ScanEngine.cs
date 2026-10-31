using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using SyScan.Desktop.Services;
using SyScan.Scanner.Correlation;
using SyScan.Scanner.FileSystem;
using SyScan.Scanner.Games;
using SyScan.Scanner.Historical;
using SyScan.Scanner.Ntfs;
using SyScan.Scanner.Signatures;

namespace SyScan.Desktop.Scanner;

public record ModuleRunResult(bool Success, string Status, int FindingsCount, string? ErrorMessage = null);

public class ScanEngine
{
    private readonly ApiClient _api;
    private readonly SignatureEngine _signatureEngine = new();
    private readonly GameInvestigationEngine _gameEngine = new();

    // Cache of collected artifacts for final correlation
    private readonly List<ForensicFileRecord> _collectedFiles = new();
    private readonly List<PrefetchEntry> _collectedPrefetch = new();
    private readonly List<BamDamEntry> _collectedBam = new();
    private readonly List<ShimcacheEntry> _collectedShimcache = new();
    private DeletionInvestigationResult? _collectedUsnResult;
    private readonly List<GameInvestigationResult> _collectedGameResults = new();
    private readonly List<SignatureMatchResult> _collectedSignatureMatches = new();

    public ScanEngine(ApiClient api)
    {
        _api = api;
    }

    public async Task<ModuleRunResult> RunModuleAsync(string moduleId, CancellationToken ct)
    {
        try
        {
            return moduleId switch
            {
                "process-scanner" => await ScanProcessesAsync(ct),
                "service-scanner" => await ScanServicesAsync(ct),
                "driver-scanner" => await ScanDriversAsync(ct),
                "game-directory" => await ScanGameDirectoryAsync(ct),
                "game-log-analyzer" => await AnalyzeGameLogsAsync(ct),
                "file-system-scanner" => await ScanFileSystemAsync(ct),
                "forensic-artifacts" => await ScanForensicArtifactsAsync(ct),
                "installed-apps" => await ScanInstalledAppsAsync(ct),
                "registry-scanner" => await ScanRegistryAsync(ct),
                "event-log-scanner" => await ScanEventLogsAsync(ct),
                "file-deletion" => await ScanFileDeletionAsync(ct),
                "anti-forensic" => await ScanAntiForensicAsync(ct),
                _ => new ModuleRunResult(false, "Failed", 0, $"Unknown module '{moduleId}'")
            };
        }
        catch (OperationCanceledException)
        {
            return new ModuleRunResult(false, "Cancelled", 0, "Scan cancelled by user.");
        }
        catch (Exception ex)
        {
            return new ModuleRunResult(false, "Failed", 0, ex.Message);
        }
    }

    #region Module 1: Process Scanner
    private async Task<ModuleRunResult> ScanProcessesAsync(CancellationToken ct)
    {
        int findings = 0;
        var processes = Process.GetProcesses();

        var knownCheatSignatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cheatengine", "cheatengine-x86_64", "x64dbg", "x32dbg", "ida64", "ida",
            "kiddions", "injector", "extremeinjector", "dllinjector", "ghinjector",
            "liquidbounce", "wurst", "aristois", "meteor", "sigma", "flux",
            "autoclicker", "speedclicker", "opautoclicker", "macrokey"
        };

        var suspiciousPaths = new[] { "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Downloads\\" };

        foreach (var p in processes)
        {
            ct.ThrowIfCancellationRequested();
            string name = p.ProcessName;
            string? mainModulePath = null;

            try
            {
                mainModulePath = p.MainModule?.FileName;
            }
            catch
            {
                // Access denied for system processes
            }

            if (knownCheatSignatures.Any(sig => name.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "process-scanner",
                    category = "Detection",
                    severity = "Critical",
                    title = $"Known Cheat / Debugger Process Active: {name}.exe",
                    description = $"Process '{name}' (PID: {p.Id}) matches known game manipulation software signature.",
                    filePath = mainModulePath ?? name,
                    fileHash = mainModulePath != null ? ComputeFileSha256(mainModulePath) : "unreadable",
                    confidence = 95,
                    explanation = "Process signature identified in known cheat catalog."
                });
            }
            else if (mainModulePath != null && suspiciousPaths.Any(sp => mainModulePath.Contains(sp, StringComparison.OrdinalIgnoreCase)))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "process-scanner",
                    category = "Suspicious",
                    severity = "Warning",
                    title = $"Executable Running from Temporary / User Directory: {name}.exe",
                    description = $"Process '{name}' (PID: {p.Id}) is running from suspicious path: {mainModulePath}",
                    filePath = mainModulePath,
                    fileHash = ComputeFileSha256(mainModulePath),
                    confidence = 70,
                    explanation = "Running executables from Temp or Downloads directories is common for loaders and ephemeral cheats."
                });
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 2: Service Scanner
    private async Task<ModuleRunResult> ScanServicesAsync(CancellationToken ct)
    {
        int findings = 0;
        var suspiciousServiceKeywords = new[] { "cheat", "hack", "bypass", "spoofer", "injector" };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey != null)
            {
                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var svcSubKey = servicesKey.OpenSubKey(svcName);
                    if (svcSubKey == null) continue;

                    string displayName = svcSubKey.GetValue("DisplayName")?.ToString() ?? svcName;
                    string imagePath = svcSubKey.GetValue("ImagePath")?.ToString() ?? "";

                    if (suspiciousServiceKeywords.Any(k => svcName.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                                                           displayName.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                                                           imagePath.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "service-scanner",
                            category = "Suspicious",
                            severity = "Warning",
                            title = $"Suspicious Service Found: {displayName} ({svcName})",
                            description = $"Service '{svcName}' matches cheat-related nomenclature. ImagePath: {imagePath}",
                            filePath = imagePath,
                            confidence = 75,
                            explanation = "Service name or binary path contains keywords associated with cheating or spoofing utilities."
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 3: Driver Scanner
    private async Task<ModuleRunResult> ScanDriversAsync(CancellationToken ct)
    {
        int findings = 0;
        var vulnerableDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "gdrv.sys", "capcom.sys", "dbk64.sys", "iqvw64e.sys", "mhyprot2.sys", "procexp.sys"
        };

        string driversPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
        if (Directory.Exists(driversPath))
        {
            var sysFiles = Directory.GetFiles(driversPath, "*.sys");
            foreach (var driver in sysFiles)
            {
                ct.ThrowIfCancellationRequested();
                string fileName = Path.GetFileName(driver);

                if (vulnerableDrivers.Contains(fileName))
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "driver-scanner",
                        category = "Detection",
                        severity = "Critical",
                        title = $"Known Vulnerable / Exploited Driver: {fileName}",
                        description = $"Driver '{fileName}' in drivers directory matches known BYOVD (Bring Your Own Vulnerable Driver) exploit list.",
                        filePath = driver,
                        fileHash = ComputeFileSha256(driver),
                        confidence = 90,
                        explanation = "Driver has known kernel vulnerabilities often abused to bypass kernel anticheat systems."
                    });
                }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 4: Game Directory Scanner
    private async Task<ModuleRunResult> ScanGameDirectoryAsync(CancellationToken ct)
    {
        int findings = 0;
        var gameResults = await _gameEngine.RunAllAsync(cancellationToken: ct);
        _collectedGameResults.AddRange(gameResults);

        foreach (var gr in gameResults)
        {
            foreach (var f in gr.Findings)
            {
                if (f.ArtifactType is "Mod" or "DllInjection" or "Executor")
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "game-directory",
                        category = "Detection",
                        severity = f.Severity,
                        title = f.FindingName,
                        description = f.Description,
                        filePath = f.FilePath,
                        fileHash = !string.IsNullOrEmpty(f.FilePath) && File.Exists(f.FilePath) ? ComputeFileSha256(f.FilePath) : "unreadable",
                        artifactTimestamp = f.TimestampUtc,
                        confidence = 88,
                        explanation = $"Detected suspicious asset in {gr.GameName} directory."
                    });
                }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 5: Game Log Analyzer
    private async Task<ModuleRunResult> AnalyzeGameLogsAsync(CancellationToken ct)
    {
        int findings = 0;

        foreach (var gr in _collectedGameResults)
        {
            foreach (var f in gr.Findings)
            {
                if (f.ArtifactType is "Log" or "JavaAgent")
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "game-log-analyzer",
                        category = f.Severity == "Critical" ? "Detection" : "Suspicious",
                        severity = f.Severity,
                        title = f.FindingName,
                        description = f.Description,
                        filePath = f.FilePath,
                        artifactTimestamp = f.TimestampUtc,
                        confidence = 85,
                        explanation = $"Historical game log analysis for {gr.GameName}."
                    });
                }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 6: Full File System Scanner
    private async Task<ModuleRunResult> ScanFileSystemAsync(CancellationToken ct)
    {
        int findings = 0;

        var targetRoots = new List<string>
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        var options = new ForensicFileInventoryOptions
        {
            MaxFilesToScan = 3000,
            MaxDirectoryDepth = 5
        };

        var fileEngine = new ForensicFileInventoryEngine(options);
        var discoveredRecords = await fileEngine.ScanDirectoriesAsync(targetRoots, null, ct);

        foreach (var record in discoveredRecords)
        {
            _collectedFiles.Add(record);

            // 1. Check for suspicious path and suspicious name
            if (record.IsSuspiciousPath && (record.Extension is ".exe" or ".dll" or ".sys"))
            {
                string lower = record.FileName.ToLowerInvariant();
                bool nameSuspicious = lower.Contains("cheat") || lower.Contains("inject") ||
                                      lower.Contains("clicker") || lower.Contains("vape") ||
                                      lower.Contains("bypass") || lower.Contains("spoofer");

                // Check digital signature
                if (!record.Signature.IsSigned || !record.Signature.IsTrustedVendor)
                {
                    if (nameSuspicious)
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "file-system-scanner",
                            category = "Detection",
                            severity = "Critical",
                            title = $"Unsigned Suspicious Executable in User Storage: {record.FileName}",
                            description = $"File '{record.FullPath}' ({record.FileSizeBytes:N0} bytes) matches cheat naming without trusted signature.",
                            filePath = record.FullPath,
                            fileHash = record.Sha256Hash,
                            artifactTimestamp = record.LastWriteTimeUtc,
                            confidence = 88,
                            explanation = "Executable located in user directory matches known game manipulation nomenclature."
                        });
                    }
                }
            }

            // 2. Scan file buffer with Signature Engine
            if (record.FileSizeBytes > 0 && record.FileSizeBytes < 10 * 1024 * 1024)
            {
                try
                {
                    var sigMatches = await _signatureEngine.ScanFileAsync(record.FullPath, ct);
                    foreach (var sm in sigMatches)
                    {
                        _collectedSignatureMatches.Add(sm);
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "file-system-scanner",
                            category = "Detection",
                            severity = sm.Severity,
                            title = $"Signature Match: {sm.RuleName} in {record.FileName}",
                            description = $"{sm.Description} [{sm.MatchedPattern}]",
                            filePath = record.FullPath,
                            fileHash = record.Sha256Hash,
                            artifactTimestamp = record.LastWriteTimeUtc,
                            confidence = 90,
                            explanation = $"Static binary signature rule '{sm.RuleId}' matched file content."
                        });
                    }
                }
                catch { }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 7: Forensic Artifact Scanner
    private async Task<ModuleRunResult> ScanForensicArtifactsAsync(CancellationToken ct)
    {
        int findings = 0;

        // 1. Scan Prefetch
        try
        {
            var pfEntries = PrefetchParser.ScanDirectory().ToList();
            _collectedPrefetch.AddRange(pfEntries);

            foreach (var pf in pfEntries)
            {
                ct.ThrowIfCancellationRequested();
                if (pf.SuspiciousLocation || pf.SuspiciousReferencedFiles.Count > 0)
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "forensic-artifacts",
                        category = "Detection",
                        severity = "High",
                        title = $"Prefetch Execution Trace: {pf.ExecutableName}",
                        description = $"Prefetch records execution from/loading suspicious paths. Run count: {pf.RunCount}. Last run: {(pf.LastExecutionTimes.Count > 0 ? pf.LastExecutionTimes[0].ToString("u") : "unknown")}",
                        filePath = pf.SourceFilePath,
                        artifactTimestamp = pf.LastExecutionTimes.FirstOrDefault(),
                        confidence = 88,
                        explanation = $"Referenced files: {string.Join("; ", pf.SuspiciousReferencedFiles.Take(3))}"
                    });
                }
            }
        }
        catch { }

        // 2. Scan Shimcache
        try
        {
            var shimEntries = ShimcacheParser.ReadFromLiveRegistry();
            _collectedShimcache.AddRange(shimEntries);

            foreach (var sh in shimEntries.Where(s => s.IsSuspicious))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "forensic-artifacts",
                    category = "Suspicious",
                    severity = "High",
                    title = $"AppCompatCache Execution Record: {Path.GetFileName(sh.Path)}",
                    description = $"Shimcache entry for '{sh.Path}' (Executed: {sh.Executed})",
                    filePath = sh.Path,
                    artifactTimestamp = sh.LastModifiedUtc,
                    confidence = 82,
                    explanation = "Windows AppCompatCache records historical executables evaluated for compatibility."
                });
            }
        }
        catch { }

        // 3. Scan BAM / DAM
        try
        {
            var bamEntries = BamDamParser.ReadFromLiveRegistry();
            _collectedBam.AddRange(bamEntries);

            foreach (var b in bamEntries.Where(b => b.IsSuspicious))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "forensic-artifacts",
                    category = "Detection",
                    severity = "High",
                    title = $"BAM/DAM Background Activity Record: {Path.GetFileName(b.NormalizedPath)}",
                    description = $"Windows {b.SourceService} confirmed past execution: '{b.NormalizedPath}'",
                    filePath = b.NormalizedPath,
                    artifactTimestamp = b.LastExecutionUtc,
                    confidence = 85,
                    explanation = $"Background Activity Moderator tracked executable under SID {b.UserSid}."
                });
            }
        }
        catch { }

        // 4. Scan Jump Lists
        try
        {
            var jumpEntries = JumpListParser.ScanRecentDestinations();
            foreach (var jl in jumpEntries.Where(j => j.IsSuspicious))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "forensic-artifacts",
                    category = "Suspicious",
                    severity = "Warning",
                    title = $"Jump List Recent Shortcut: {Path.GetFileName(jl.TargetPath)}",
                    description = $"Recent taskbar / shell destination references: '{jl.TargetPath}'",
                    filePath = jl.TargetPath,
                    artifactTimestamp = jl.TargetModifiedUtc,
                    confidence = 78,
                    explanation = "Jump List stores user application launches and accessed files."
                });
            }
        }
        catch { }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 8: Installed Application Scanner
    private async Task<ModuleRunResult> ScanInstalledAppsAsync(CancellationToken ct)
    {
        int findings = 0;
        var registryPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        var suspiciousApps = new[] { "cheat engine", "process hacker", "wireshark", "fiddler", "auto clicker", "macro recorder" };

        foreach (var regPath in registryPaths)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.LocalMachine.OpenSubKey(regPath);
            if (key == null) continue;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var subKey = key.OpenSubKey(subKeyName);
                var displayName = subKey?.GetValue("DisplayName")?.ToString();
                if (string.IsNullOrWhiteSpace(displayName)) continue;

                if (suspiciousApps.Any(s => displayName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "installed-apps",
                        category = "Warning",
                        severity = "Warning",
                        title = $"Suspicious Software Installed: {displayName}",
                        description = $"Application '{displayName}' is registered in system installed software inventory.",
                        confidence = 75,
                        explanation = "Software can be used for reverse engineering, memory tampering, or automated macros."
                    });
                }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 9: Registry Scanner
    private async Task<ModuleRunResult> ScanRegistryAsync(CancellationToken ct)
    {
        int findings = 0;
        string[] startupKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        foreach (var runKey in startupKeys)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(runKey);
            if (key == null) continue;

            foreach (var val in key.GetValueNames())
            {
                var valData = key.GetValue(val)?.ToString();
                if (string.IsNullOrEmpty(valData)) continue;

                if (valData.Contains("temp", StringComparison.OrdinalIgnoreCase) ||
                    valData.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                    valData.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "registry-scanner",
                        category = "Suspicious",
                        severity = "Warning",
                        title = $"Suspicious Startup Registry Entry: {val}",
                        description = $"Startup entry '{val}' points to '{valData}'",
                        filePath = valData,
                        confidence = 78,
                        explanation = "Persistence mechanism identified in user Run/RunOnce registry hive."
                    });
                }
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 10: Event Log Scanner
    private async Task<ModuleRunResult> ScanEventLogsAsync(CancellationToken ct)
    {
        int findings = 0;
        try
        {
            using var log = new EventLog("System");
            int scanned = 0;
            for (int i = log.Entries.Count - 1; i >= 0 && scanned < 500; i--, scanned++)
            {
                ct.ThrowIfCancellationRequested();
                var entry = log.Entries[i];

                if (entry.InstanceId == 1102 || entry.InstanceId == 104)
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "event-log-scanner",
                        category = "Integrity",
                        severity = "Critical",
                        title = "Event Log Cleared Indicator Detected",
                        description = $"Event ID {entry.InstanceId} recorded at {entry.TimeGenerated:u}. The system audit log was cleared.",
                        artifactTimestamp = entry.TimeGenerated.ToUniversalTime(),
                        confidence = 95,
                        explanation = "Log clearing is an anti-forensic action often performed after cheat execution."
                    });
                }
                else if (entry.InstanceId == 7045 && entry.Message.Contains(".sys", StringComparison.OrdinalIgnoreCase))
                {
                    if (entry.Message.Contains("capcom", StringComparison.OrdinalIgnoreCase) ||
                        entry.Message.Contains("gdrv", StringComparison.OrdinalIgnoreCase))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "event-log-scanner",
                            category = "Detection",
                            severity = "Critical",
                            title = "Vulnerable Driver Service Installation Event Recorded",
                            description = $"Event ID 7045: Service installation detected: {entry.Message}",
                            artifactTimestamp = entry.TimeGenerated.ToUniversalTime(),
                            confidence = 90,
                            explanation = "Windows event record proves installation of vulnerable driver service."
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            return new ModuleRunResult(true, "Partial", findings, $"Limited EventLog access: {ex.Message}");
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 11: File Deletion Scanner
    private async Task<ModuleRunResult> ScanFileDeletionAsync(CancellationToken ct)
    {
        int findings = 0;

        // 1. Scan NTFS USN Change Journal
        try
        {
            var usnResult = UsnJournalReader.ScanLiveVolumeJournal("C:", 10000);
            _collectedUsnResult = usnResult;

            if (usnResult.VolumeJournalAccessible)
            {
                // Report rename-before-delete sequences
                foreach (var rbd in usnResult.RenamedBeforeDelete.Where(r => r.IsFileDelete))
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "file-deletion",
                        category = "Detection",
                        severity = "Critical",
                        title = $"Renamed and Deleted Binary in USN Journal: {rbd.FileName}",
                        description = $"File was renamed before deletion in NTFS USN Change Journal (FRN: {rbd.FileReferenceNumber})",
                        filePath = rbd.FileName,
                        artifactTimestamp = rbd.TimestampUtc,
                        confidence = 92,
                        explanation = "Anti-forensic pattern: binary renamed prior to deletion to evade static inspection."
                    });
                }

                // Report suspicious deletions
                foreach (var suspDel in usnResult.SuspiciousGameDeletions.Take(10))
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "file-deletion",
                        category = "Suspicious",
                        severity = "High",
                        title = $"Recently Deleted Executable in USN Journal: {suspDel.FileName}",
                        description = $"NTFS Journal recorded deletion at {suspDel.TimestampUtc:u}",
                        filePath = suspDel.FileName,
                        artifactTimestamp = suspDel.TimestampUtc,
                        confidence = 80,
                        explanation = "Recently deleted executable or DLL detected via NTFS USN Journal."
                    });
                }
            }
        }
        catch { }

        // 2. Scan Recycle Bin
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string driveLetter = Path.GetPathRoot(userProfile) ?? "C:\\";
        string recyclePath = Path.Combine(driveLetter, "$Recycle.Bin");

        if (Directory.Exists(recyclePath))
        {
            try
            {
                var files = Directory.GetFiles(recyclePath, "*.*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string fileName = Path.GetFileName(file);
                    if (fileName.StartsWith("$R", StringComparison.OrdinalIgnoreCase) &&
                        (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "file-deletion",
                            category = "Suspicious",
                            severity = "Warning",
                            title = $"Deleted Executable In Recycle Bin: {fileName}",
                            description = $"Deleted binary retained in Recycle Bin: '{file}'",
                            filePath = file,
                            fileHash = ComputeFileSha256(file),
                            artifactTimestamp = File.GetLastWriteTimeUtc(file),
                            confidence = 75,
                            explanation = "Deleted executable file trace found in Recycle Bin metadata."
                        });
                    }
                }
            }
            catch { }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 12: Anti-Forensic Scanner & Evidence Correlation
    private async Task<ModuleRunResult> ScanAntiForensicAsync(CancellationToken ct)
    {
        int findings = 0;

        // 1. Check if Prefetch is disabled in Registry
        string sessionManager = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
        using (var key = Registry.LocalMachine.OpenSubKey(sessionManager))
        {
            if (key != null)
            {
                var val = key.GetValue("EnablePrefetcher");
                if (val is int intVal && intVal == 0)
                {
                    findings++;
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "anti-forensic",
                        category = "Integrity",
                        severity = "Warning",
                        title = "Windows Prefetching is Disabled",
                        description = "Registry value 'EnablePrefetcher' is set to 0. Execution forensics will be limited.",
                        confidence = 85,
                        explanation = "Prefetching was disabled, preventing execution trace retention."
                    });
                }
            }
        }

        // 2. Timestomp detection on collected files
        foreach (var file in _collectedFiles.Where(f => f.IsSuspiciousPath).Take(50))
        {
            ct.ThrowIfCancellationRequested();
            var ts = TimestompDetector.AnalyzeFile(file.FullPath);
            if (ts.TimestompDetected)
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "anti-forensic",
                    category = "Integrity",
                    severity = "Critical",
                    title = $"Timestomped File Detected: {file.FileName}",
                    description = ts.DetectionReason,
                    filePath = file.FullPath,
                    artifactTimestamp = ts.CreationTimeUtc,
                    confidence = 90,
                    explanation = "Programmatic timestamp modification identified, indicating intent to disguise file history."
                });
            }
        }

        // 3. Evidence Correlation: Correlate all discovered artifacts across all modules!
        try
        {
            var correlationReport = EvidenceCorrelationEngine.Correlate(
                _collectedFiles,
                _collectedPrefetch,
                _collectedBam,
                _collectedShimcache,
                _collectedUsnResult,
                _collectedGameResults,
                _collectedSignatureMatches);

            foreach (var incident in correlationReport.Incidents)
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "anti-forensic",
                    category = "Detection",
                    severity = incident.ConfidenceScore,
                    title = $"Correlated Incident: {incident.PrimaryExecutable} ({incident.ConfidenceScore} Confidence)",
                    description = $"{incident.Summary} Events: {incident.TimelineEvents.Count}",
                    filePath = incident.TimelineEvents.FirstOrDefault(e => !string.IsNullOrEmpty(e.FilePath))?.FilePath ?? incident.PrimaryExecutable,
                    artifactTimestamp = incident.TimelineEvents.FirstOrDefault()?.TimestampUtc,
                    confidence = incident.ConfidencePercent,
                    explanation = $"Corroborated across forensic layers: {string.Join(", ", incident.CorroboratingSources)}"
                });
            }
        }
        catch { }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Helper Methods
    private static string ComputeFileSha256(string filePath)
    {
        try
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return "hash_unavailable";
        }
    }
    #endregion
}
