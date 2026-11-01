using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using SyScan.Scanner.Allowlist;
using SyScan.Scanner.FileSystem;
using SyScan.Scanner.Historical;
using SyScan.Scanner.IPC;
using SyScan.Scanner.Ntfs;
using SyScan.Scanner.Recon;

namespace SyScan.Collector;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        string? pipeNonce = null;
        int parentPid = -1;

        foreach (var arg in args)
        {
            if (arg.StartsWith("--pipe-nonce=", StringComparison.OrdinalIgnoreCase))
                pipeNonce = arg["--pipe-nonce=".Length..].Trim();
            else if (arg.StartsWith("--parent-pid=", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(arg["--parent-pid=".Length..], out int pid))
                    parentPid = pid;
            }
        }

        if (string.IsNullOrWhiteSpace(pipeNonce))
        {
            Console.Error.WriteLine("Error: Missing --pipe-nonce parameter.");
            return 1;
        }

        bool isElevated = false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { }

        // Watch parent process if supplied
        var cts = new CancellationTokenSource();
        if (parentPid > 0)
        {
            try
            {
                var parentProc = Process.GetProcessById(parentPid);
                parentProc.EnableRaisingEvents = true;
                parentProc.Exited += (_, _) => cts.Cancel();
            }
            catch
            {
                // Parent already dead
                return 0;
            }
        }

        string pipeName = $"SyScan_Collector_{pipeNonce}";
        using var server = new CollectorIpcServer(pipeName, pipeNonce, req => HandleRequestAsync(req, isElevated));
        server.Start();

        try
        {
            await Task.Delay(-1, cts.Token);
        }
        catch (OperationCanceledException) { }

        return 0;
    }

    private static Task<CollectorResponse> HandleRequestAsync(CollectorRequest request, bool isElevated)
    {
        switch (request.Command)
        {
            case IpcCommands.Ping:
                return Task.FromResult(new CollectorResponse
                {
                    RequestId = request.RequestId,
                    Success = true,
                    IsElevated = isElevated,
                    Status = "Pong"
                });

            case IpcCommands.GetRecon:
                var reconData = SystemReconnaissance.Collect();
                return Task.FromResult(new CollectorResponse
                {
                    RequestId = request.RequestId,
                    Success = true,
                    IsElevated = isElevated,
                    DataJson = JsonSerializer.Serialize(reconData)
                });

            case IpcCommands.ScanPrefetch:
                try
                {
                    var prefetch = PrefetchParser.ScanDirectory().ToList();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = prefetch.Count,
                        DataJson = JsonSerializer.Serialize(prefetch)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        Status = isElevated ? "Failed" : "PermissionDenied",
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanAmcache:
                try
                {
                    var amcache = AmcacheParser.ScanSystem();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = amcache.Count,
                        DataJson = JsonSerializer.Serialize(amcache)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        Status = isElevated ? "Failed" : "PermissionDenied",
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanShimcache:
                try
                {
                    var shimcache = ShimcacheParser.ReadFromLiveRegistry();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = shimcache.Count,
                        DataJson = JsonSerializer.Serialize(shimcache)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanBamDam:
                try
                {
                    var bam = BamDamParser.ReadFromLiveRegistry();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = bam.Count,
                        DataJson = JsonSerializer.Serialize(bam)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanSrum:
                try
                {
                    var srum = SrumParser.Analyze();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = srum.SrumDatabaseAccessible,
                        IsElevated = isElevated,
                        Status = srum.SrumDatabaseAccessible ? "Completed" : (isElevated ? "Failed" : "PermissionDenied"),
                        DataJson = JsonSerializer.Serialize(srum)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanUsnJournal:
                try
                {
                    string drive = request.Parameters.GetValueOrDefault("drive", "C:");
                    var usnResult = UsnJournalReader.ScanLiveVolumeJournal(drive, 10000);
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = usnResult.VolumeJournalAccessible,
                        IsElevated = isElevated,
                        Status = usnResult.VolumeJournalAccessible ? "Completed" : "PermissionDenied",
                        RecordsCount = usnResult.TotalRecordsAnalyzed,
                        DataJson = JsonSerializer.Serialize(usnResult),
                        ErrorMessage = usnResult.VolumeJournalAccessible ? null : usnResult.StatusMessage
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanServicesAndDrivers:
                try
                {
                    var list = CollectPrivilegedServicesAndDrivers();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = list.Count,
                        DataJson = JsonSerializer.Serialize(list)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.ScanProcesses:
                try
                {
                    var procs = CollectRunningProcesses();
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = true,
                        IsElevated = isElevated,
                        RecordsCount = procs.Count,
                        DataJson = JsonSerializer.Serialize(procs)
                    });
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new CollectorResponse
                    {
                        RequestId = request.RequestId,
                        Success = false,
                        IsElevated = isElevated,
                        ErrorMessage = ex.Message
                    });
                }

            case IpcCommands.Shutdown:
                return Task.FromResult(new CollectorResponse
                {
                    RequestId = request.RequestId,
                    Success = true,
                    Status = "ShuttingDown"
                });

            default:
                return Task.FromResult(new CollectorResponse
                {
                    RequestId = request.RequestId,
                    Success = false,
                    Status = "UnsupportedCommand",
                    ErrorMessage = $"Command '{request.Command}' is not permitted."
                });
        }
    }

    private static List<PrivilegedServiceRecord> CollectPrivilegedServicesAndDrivers()
    {
        var records = new List<PrivilegedServiceRecord>();
        using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (servicesKey == null) return records;

        foreach (var svcName in servicesKey.GetSubKeyNames())
        {
            using var svcKey = servicesKey.OpenSubKey(svcName);
            if (svcKey == null) continue;

            string displayName = svcKey.GetValue("DisplayName")?.ToString() ?? svcName;
            string imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? "";
            int type = 0;
            object? typeVal = svcKey.GetValue("Type");
            if (typeVal is int t) type = t;

            bool isDriver = (type & 0x00000001) != 0 || (type & 0x00000002) != 0 || imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);

            // Check if verified legitimate anti-cheat (EasyAntiCheat, BattlEye, Vanguard)
            bool isLegitAntiCheat = isDriver
                ? AntiCheatAllowlist.IsLegitimateAntiCheatDriver(svcName, imagePath)
                : AntiCheatAllowlist.IsLegitimateAntiCheatService(svcName, displayName, imagePath);

            records.Add(new PrivilegedServiceRecord
            {
                ServiceName = svcName,
                DisplayName = displayName,
                ImagePath = imagePath,
                IsDriver = isDriver,
                IsLegitimateAntiCheat = isLegitAntiCheat
            });
        }

        return records;
    }

    private static List<ProcessSnapshotRecord> CollectRunningProcesses()
    {
        var list = new List<ProcessSnapshotRecord>();
        foreach (var p in Process.GetProcesses())
        {
            string name = p.ProcessName;
            int pid = p.Id;
            string? mainModulePath = null;
            DateTime? startTime = null;

            try
            {
                mainModulePath = p.MainModule?.FileName;
                startTime = p.StartTime.ToUniversalTime();
            }
            catch { }

            // Suppress SyScan self-detection
            bool isSelf = SyScanIdentity.IsSyScanComponent(mainModulePath, name);

            list.Add(new ProcessSnapshotRecord
            {
                Pid = pid,
                Name = name,
                ExecutablePath = mainModulePath ?? name,
                StartTimeUtc = startTime,
                IsSyScan = isSelf
            });
        }

        return list;
    }
}

public sealed class PrivilegedServiceRecord
{
    public string ServiceName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;
    public bool IsDriver { get; set; }
    public bool IsLegitimateAntiCheat { get; set; }
}

public sealed class ProcessSnapshotRecord
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public DateTime? StartTimeUtc { get; set; }
    public bool IsSyScan { get; set; }
}

