using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SyScan.Scanner.FileSystem;
using SyScan.Scanner.Games;
using SyScan.Scanner.Historical;
using SyScan.Scanner.Ntfs;
using SyScan.Scanner.Signatures;

namespace SyScan.Scanner.Correlation;

public sealed class TimelineEvent
{
    public DateTime TimestampUtc { get; set; }
    public string SourceArtifact { get; set; } = string.Empty; // "Prefetch", "BAM", "Shimcache", "USN", "FileSystem", "GameLog", "Signature"
    public string EventType { get; set; } = string.Empty; // "Created", "Executed", "Renamed", "Deleted", "SignatureMatched"
    public string EntityName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = "Low";
}

public sealed class CorrelatedIncident
{
    public string IncidentId { get; set; } = Guid.NewGuid().ToString("N");
    public string PrimaryExecutable { get; set; } = string.Empty;
    public string ConfidenceScore { get; set; } = "Medium"; // Low, Medium, High, Critical
    public int ConfidencePercent { get; set; } = 50;
    public string Summary { get; set; } = string.Empty;
    public List<TimelineEvent> TimelineEvents { get; set; } = new();
    public List<string> CorroboratingSources { get; set; } = new();
}

public sealed class CorrelationReport
{
    public List<CorrelatedIncident> Incidents { get; set; } = new();
    public List<TimelineEvent> CompleteChronologicalTimeline { get; set; } = new();
    public int TotalArtifactsAnalyzed { get; set; }
}

public static class EvidenceCorrelationEngine
{
    public static CorrelationReport Correlate(
        IEnumerable<ForensicFileRecord>? files,
        IEnumerable<PrefetchEntry>? prefetchEntries,
        IEnumerable<BamDamEntry>? bamEntries,
        IEnumerable<ShimcacheEntry>? shimEntries,
        DeletionInvestigationResult? usnResult,
        IEnumerable<GameInvestigationResult>? gameResults,
        IEnumerable<SignatureMatchResult>? signatureMatches)
    {
        var allEvents = new List<TimelineEvent>();

        // 1. Ingest File System Events
        if (files != null)
        {
            foreach (var f in files)
            {
                allEvents.Add(new TimelineEvent
                {
                    TimestampUtc = f.CreationTimeUtc,
                    SourceArtifact = "FileSystem",
                    EventType = "Created",
                    EntityName = f.FileName,
                    FilePath = f.FullPath,
                    Description = $"File creation on filesystem (SHA256: {f.Sha256Hash[..Math.Min(8, f.Sha256Hash.Length)]}..)",
                    Severity = f.IsSuspiciousPath ? "Medium" : "Low"
                });

                allEvents.Add(new TimelineEvent
                {
                    TimestampUtc = f.LastWriteTimeUtc,
                    SourceArtifact = "FileSystem",
                    EventType = "Modified",
                    EntityName = f.FileName,
                    FilePath = f.FullPath,
                    Description = "Last write timestamp on filesystem",
                    Severity = "Low"
                });
            }
        }

        // 2. Ingest Prefetch Events
        if (prefetchEntries != null)
        {
            foreach (var pf in prefetchEntries)
            {
                foreach (var t in pf.LastExecutionTimes)
                {
                    allEvents.Add(new TimelineEvent
                    {
                        TimestampUtc = t,
                        SourceArtifact = "Prefetch",
                        EventType = "Executed",
                        EntityName = pf.ExecutableName,
                        FilePath = pf.SourceFilePath,
                        Description = $"Windows Prefetch execution recorded (Run count: {pf.RunCount})",
                        Severity = pf.SuspiciousLocation ? "High" : "Low"
                    });
                }
            }
        }

        // 3. Ingest BAM / DAM Events
        if (bamEntries != null)
        {
            foreach (var b in bamEntries)
            {
                if (b.LastExecutionUtc.HasValue)
                {
                    allEvents.Add(new TimelineEvent
                    {
                        TimestampUtc = b.LastExecutionUtc.Value,
                        SourceArtifact = b.SourceService,
                        EventType = "Executed",
                        EntityName = Path.GetFileName(b.NormalizedPath),
                        FilePath = b.NormalizedPath,
                        Description = $"Windows {b.SourceService} recorded execution for SID {b.UserSid}",
                        Severity = b.IsSuspicious ? "High" : "Low"
                    });
                }
            }
        }

        // 4. Ingest Shimcache Events
        if (shimEntries != null)
        {
            foreach (var sh in shimEntries)
            {
                if (sh.LastModifiedUtc.HasValue)
                {
                    allEvents.Add(new TimelineEvent
                    {
                        TimestampUtc = sh.LastModifiedUtc.Value,
                        SourceArtifact = "Shimcache",
                        EventType = sh.Executed ? "Executed" : "Registered",
                        EntityName = Path.GetFileName(sh.Path),
                        FilePath = sh.Path,
                        Description = $"AppCompatCache entry (Executed: {sh.Executed})",
                        Severity = sh.IsSuspicious ? "High" : "Low"
                    });
                }
            }
        }

        // 5. Ingest USN Journal Events
        if (usnResult != null)
        {
            foreach (var del in usnResult.RecentDeletions)
            {
                allEvents.Add(new TimelineEvent
                {
                    TimestampUtc = del.TimestampUtc,
                    SourceArtifact = "USN_Journal",
                    EventType = "Deleted",
                    EntityName = del.FileName,
                    FilePath = del.FileName,
                    Description = $"NTFS USN Journal recorded file deletion (FRN: {del.FileReferenceNumber})",
                    Severity = del.IsSuspicious ? "High" : "Low"
                });
            }

            foreach (var ren in usnResult.RenamedBeforeDelete)
            {
                allEvents.Add(new TimelineEvent
                {
                    TimestampUtc = ren.TimestampUtc,
                    SourceArtifact = "USN_Journal",
                    EventType = "Renamed",
                    EntityName = ren.FileName,
                    FilePath = ren.FileName,
                    Description = $"File renamed prior to deletion in USN Journal",
                    Severity = "High"
                });
            }
        }

        // 6. Ingest Game Findings
        if (gameResults != null)
        {
            foreach (var gr in gameResults)
            {
                foreach (var gf in gr.Findings)
                {
                    allEvents.Add(new TimelineEvent
                    {
                        TimestampUtc = gf.TimestampUtc ?? DateTime.UtcNow,
                        SourceArtifact = $"GameLog_{gr.GameName}",
                        EventType = "GameArtifact",
                        EntityName = gf.FindingName,
                        FilePath = gf.FilePath,
                        Description = gf.Description,
                        Severity = gf.Severity
                    });
                }
            }
        }

        // 7. Ingest Signatures
        if (signatureMatches != null)
        {
            foreach (var sm in signatureMatches)
            {
                allEvents.Add(new TimelineEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    SourceArtifact = "SignatureEngine",
                    EventType = "SignatureMatched",
                    EntityName = sm.RuleName,
                    FilePath = sm.FilePath,
                    Description = $"{sm.Description} ({sm.MatchedPattern})",
                    Severity = sm.Severity
                });
            }
        }

        // Sort all events chronologically
        var sortedTimeline = allEvents.OrderBy(e => e.TimestampUtc).ToList();

        // 8. Group into Correlated Incidents by Base Executable Name / Entity
        var incidents = new List<CorrelatedIncident>();
        var groupedByName = allEvents
            .Where(e => !string.IsNullOrWhiteSpace(e.EntityName) && e.EntityName.Contains('.'))
            .GroupBy(e => Path.GetFileNameWithoutExtension(e.EntityName).ToLowerInvariant());

        foreach (var group in groupedByName)
        {
            var eventList = group.OrderBy(e => e.TimestampUtc).ToList();
            var sources = eventList.Select(e => e.SourceArtifact).Distinct().ToList();

            // Only promote to incident if high severity or multiple corroborated sources
            bool hasHighSeverity = eventList.Any(e => e.Severity is "High" or "Critical");
            if (sources.Count >= 2 || hasHighSeverity)
            {
                int score = 30 + (sources.Count * 20);
                if (eventList.Any(e => e.EventType == "Deleted")) score += 20;
                if (eventList.Any(e => e.EventType == "SignatureMatched")) score += 25;
                if (score > 100) score = 100;

                string confidence = score switch
                {
                    >= 85 => "Critical",
                    >= 65 => "High",
                    >= 40 => "Medium",
                    _ => "Low"
                };

                string exeName = group.Key;
                var sample = eventList.FirstOrDefault(e => !string.IsNullOrEmpty(e.EntityName));
                if (sample != null) exeName = sample.EntityName;

                incidents.Add(new CorrelatedIncident
                {
                    PrimaryExecutable = exeName,
                    ConfidenceScore = confidence,
                    ConfidencePercent = score,
                    Summary = $"Detected multi-source historical activity for '{exeName}' across {sources.Count} forensic sources ({string.Join(", ", sources)}).",
                    TimelineEvents = eventList,
                    CorroboratingSources = sources
                });
            }
        }

        return new CorrelationReport
        {
            Incidents = incidents.OrderByDescending(i => i.ConfidencePercent).ToList(),
            CompleteChronologicalTimeline = sortedTimeline,
            TotalArtifactsAnalyzed = allEvents.Count
        };
    }
}
