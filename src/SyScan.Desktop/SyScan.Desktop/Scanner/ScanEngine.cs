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

namespace SyScan.Desktop.Scanner;

public record ModuleRunResult(bool Success, string Status, int FindingsCount, string? ErrorMessage = null);

public class ScanEngine
{
    private readonly ApiClient _api;

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
                // Access denied for system processes (normal in Windows without elevated rights)
            }

            // Check known cheat name
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
                    filePath = mainModulePath ?? $"PID {p.Id}",
                    confidence = 95,
                    explanation = "Process signature detected in active memory table."
                });
            }
            // Check process executing from temp or downloads directory
            else if (!string.IsNullOrEmpty(mainModulePath) &&
                     suspiciousPaths.Any(sp => mainModulePath.Contains(sp, StringComparison.OrdinalIgnoreCase)))
            {
                findings++;
                await _api.SubmitFindingAsync(new
                {
                    moduleId = "process-scanner",
                    category = "Suspicious",
                    severity = "Warning",
                    title = $"Process Executing from Temporary Directory: {name}.exe",
                    description = $"Process '{name}' (PID: {p.Id}) is running from '{mainModulePath}'.",
                    filePath = mainModulePath,
                    confidence = 70,
                    explanation = "Legitimate applications rarely execute persistently from temporary folders."
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
        var suspiciousServices = new[] { "capcom", "kprocesshacker", "dbkp", "eneio", "gdrv", "winring0" };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey != null)
            {
                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string lowerSvc = svcName.ToLowerInvariant();

                    if (suspiciousServices.Any(s => lowerSvc.Contains(s)))
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        var displayName = svcKey?.GetValue("DisplayName")?.ToString() ?? svcName;
                        var imagePath = svcKey?.GetValue("ImagePath")?.ToString();

                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "service-scanner",
                            category = "Detection",
                            severity = "Critical",
                            title = $"Vulnerable / Known Exploit Service Found: {displayName}",
                            description = $"Service '{svcName}' (ImagePath: '{imagePath}') is known to be leveraged for kernel cheat bypass.",
                            filePath = imagePath,
                            confidence = 90,
                            explanation = "Known vulnerable signed driver / service wrapper present in system registry."
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            return new ModuleRunResult(false, "Partial", findings, $"Service enumeration error: {ex.Message}");
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 3: Driver Scanner
    private async Task<ModuleRunResult> ScanDriversAsync(CancellationToken ct)
    {
        int findings = 0;
        string driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");

        if (Directory.Exists(driversDir))
        {
            var blacklistedDrivers = new[] { "gdrv.sys", "procexp.sys", "kprocesshacker.sys", "capcom.sys", "mhyprot2.sys" };
            var files = Directory.GetFiles(driversDir, "*.sys");

            foreach (var driverFile in files)
            {
                ct.ThrowIfCancellationRequested();
                string fileName = Path.GetFileName(driverFile);

                if (blacklistedDrivers.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                {
                    findings++;
                    string hash = ComputeFileSha256(driverFile);
                    await _api.SubmitFindingAsync(new
                    {
                        moduleId = "driver-scanner",
                        category = "Detection",
                        severity = "Critical",
                        title = $"Vulnerable / Blacklisted Driver File Present: {fileName}",
                        description = $"Driver file '{driverFile}' found in System32\\drivers.",
                        filePath = driverFile,
                        fileHash = hash,
                        confidence = 92,
                        explanation = "Driver has known arbitrary read/write physical memory vulnerabilities abused by kernel bypasses."
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
        bool foundAnyGame = false;

        // Check Minecraft directory
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string mcDir = Path.Combine(appData, ".minecraft");

        if (Directory.Exists(mcDir))
        {
            foundAnyGame = true;
            string modsDir = Path.Combine(mcDir, "mods");
            if (Directory.Exists(modsDir))
            {
                var modFiles = Directory.GetFiles(modsDir, "*.jar");
                var cheatKeywords = new[] { "cheat", "hack", "xray", "wurst", "liquid", "meteor", "baritone", "clicker", "aim" };

                foreach (var mod in modFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    string modName = Path.GetFileName(mod);
                    if (cheatKeywords.Any(k => modName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "game-directory",
                            category = "Detection",
                            severity = "Critical",
                            title = $"Suspicious Mod in Minecraft Directory: {modName}",
                            description = $"Mod file '{mod}' matched known cheat pattern.",
                            filePath = mod,
                            fileHash = ComputeFileSha256(mod),
                            confidence = 88,
                            explanation = "Disallowed client mod detected in .minecraft/mods."
                        });
                    }
                }
            }
        }

        // Check FiveM directory
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string fivemDir = Path.Combine(localAppData, "FiveM", "FiveM.app");

        if (Directory.Exists(fivemDir))
        {
            foundAnyGame = true;
            string pluginsDir = Path.Combine(fivemDir, "plugins");
            if (Directory.Exists(pluginsDir))
            {
                var dlls = Directory.GetFiles(pluginsDir, "*.dll");
                foreach (var dll in dlls)
                {
                    ct.ThrowIfCancellationRequested();
                    string dllName = Path.GetFileName(dll);
                    if (dllName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        dllName.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                        dllName.Contains("hook", StringComparison.OrdinalIgnoreCase))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "game-directory",
                            category = "Detection",
                            severity = "Critical",
                            title = $"Unverified DLL in FiveM Plugins: {dllName}",
                            description = $"Plugin file '{dll}' flagged as potential executor/menu hook.",
                            filePath = dll,
                            fileHash = ComputeFileSha256(dll),
                            confidence = 85,
                            explanation = "Third-party DLL present in FiveM application plugins directory."
                        });
                    }
                }
            }
        }

        if (!foundAnyGame)
        {
            return new ModuleRunResult(true, "Completed", 0, "No supported game directory found in default locations.");
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 5: Game Log Analyzer
    private async Task<ModuleRunResult> AnalyzeGameLogsAsync(CancellationToken ct)
    {
        int findings = 0;
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string mcLogsDir = Path.Combine(appData, ".minecraft", "logs");

        if (Directory.Exists(mcLogsDir))
        {
            string latestLog = Path.Combine(mcLogsDir, "latest.log");
            if (File.Exists(latestLog))
            {
                try
                {
                    using var stream = new FileStream(latestLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(stream);
                    string? line;
                    int lineNum = 0;

                    var suspiciousPatterns = new[]
                    {
                        new Regex(@"javaagent:(.*\.jar)", RegexOptions.IgnoreCase),
                        new Regex(@"(wurst|liquidbounce|meteor|sigma|baritone)", RegexOptions.IgnoreCase),
                        new Regex(@"injection|injected|hooking", RegexOptions.IgnoreCase)
                    };

                    while ((line = await reader.ReadLineAsync(ct)) != null && lineNum < 5000)
                    {
                        lineNum++;
                        foreach (var pattern in suspiciousPatterns)
                        {
                            if (pattern.IsMatch(line))
                            {
                                findings++;
                                await _api.SubmitFindingAsync(new
                                {
                                    moduleId = "game-log-analyzer",
                                    category = "Suspicious",
                                    severity = "Warning",
                                    title = $"Cheat Indicator in Game Log (Line {lineNum})",
                                    description = $"Log entry matches indicator: {line.Trim()}",
                                    filePath = latestLog,
                                    confidence = 80,
                                    explanation = "Log entry indicates modification, injection, or disallowed client activity."
                                });
                                break;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    return new ModuleRunResult(false, "Partial", findings, $"Error reading log: {ex.Message}");
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
        var targetDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop")
        };

        var suspiciousNames = new[] { "cheat", "hack", "injector", "aimbot", "esp", "spoofer", "bypass", "clicker" };

        foreach (var dir in targetDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                var files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase));

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string fileName = Path.GetFileName(file);

                    if (suspiciousNames.Any(s => fileName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "file-system-scanner",
                            category = "Detection",
                            severity = "Critical",
                            title = $"Suspicious Executable Found in User Directory: {fileName}",
                            description = $"File '{file}' matches cheat utility nomenclature.",
                            filePath = file,
                            fileHash = ComputeFileSha256(file),
                            artifactTimestamp = File.GetLastWriteTimeUtc(file),
                            confidence = 85,
                            explanation = "Binary located in user storage matching game manipulation naming."
                        });
                    }
                }
            }
            catch
            {
                // Ignore permission errors in specific subdirectories
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 7: Forensic Artifact Scanner
    private async Task<ModuleRunResult> ScanForensicArtifactsAsync(CancellationToken ct)
    {
        int findings = 0;

        // Inspect UserAssist in HKCU
        string userAssistKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        using var rootKey = Registry.CurrentUser.OpenSubKey(userAssistKey);
        if (rootKey != null)
        {
            foreach (var subKeyName in rootKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var ceKey = rootKey.OpenSubKey($@"{subKeyName}\Count");
                if (ceKey == null) continue;

                foreach (var valName in ceKey.GetValueNames())
                {
                    string decoded = Rot13(valName);
                    if (decoded.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        decoded.Contains("injector", StringComparison.OrdinalIgnoreCase) ||
                        decoded.Contains("clicker", StringComparison.OrdinalIgnoreCase))
                    {
                        findings++;
                        await _api.SubmitFindingAsync(new
                        {
                            moduleId = "forensic-artifacts",
                            category = "Detection",
                            severity = "Critical",
                            title = $"UserAssist Execution Artifact Found: {Path.GetFileName(decoded)}",
                            description = $"Registry execution record proves past execution of: {decoded}",
                            filePath = decoded,
                            confidence = 90,
                            explanation = "Windows UserAssist maintains encrypted ROT13 history of GUI program launches."
                        });
                    }
                }
            }
        }

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

                // Event ID 1102: The audit log was cleared
                // Event ID 104: The system log was cleared
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
                // Event ID 7045: A service was installed in the system
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

        // Inspect User's Recycle Bin folder directly
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
                    if (fileName.StartsWith("$R", StringComparison.OrdinalIgnoreCase))
                    {
                        // Check if file is executable or DLL
                        if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                            fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
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
            }
            catch
            {
                // Recycle bin can have restricted subfolders
            }
        }

        return new ModuleRunResult(true, "Completed", findings);
    }
    #endregion

    #region Module 12: Anti-Forensic Scanner
    private async Task<ModuleRunResult> ScanAntiForensicAsync(CancellationToken ct)
    {
        int findings = 0;

        // Check if Prefetch is disabled in Registry
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

        // Check USN journal status
        // If USN Journal was wiped or truncated recently
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

    private static string Rot13(string input)
    {
        var array = input.ToCharArray();
        for (int i = 0; i < array.Length; i++)
        {
            int number = array[i];
            if (number is >= 'a' and <= 'z')
            {
                if (number > 'm') number -= 13;
                else number += 13;
            }
            else if (number is >= 'A' and <= 'Z')
            {
                if (number > 'M') number -= 13;
                else number += 13;
            }
            array[i] = (char)number;
        }
        return new string(array);
    }
    #endregion
}
