using System;
using System.Collections.Generic;

namespace SyScan.Scanner.Signatures;

public enum RuleCategory
{
    AutoClicker,
    Injector,
    MemoryPatcher,
    Overlay,
    CheatLoader,
    AntiForensicTool
}

public sealed class BytePattern
{
    public byte?[] Pattern { get; set; } = Array.Empty<byte?>();
    public string Description { get; set; } = string.Empty;
}

public sealed class DetectionRule
{
    public string RuleId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public RuleCategory Category { get; set; }
    public string Severity { get; set; } = "High"; // Low, Medium, High, Critical
    public string Description { get; set; } = string.Empty;
    public string TargetGame { get; set; } = "Universal";
    public List<string> StringPatterns { get; set; } = new();
    public List<BytePattern> BytePatterns { get; set; } = new();
    public HashSet<string> TargetSha256Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class SignatureMatchResult
{
    public string RuleId { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public RuleCategory Category { get; set; }
    public string Severity { get; set; } = "High";
    public string Description { get; set; } = string.Empty;
    public string MatchedPattern { get; set; } = string.Empty;
    public long MatchOffset { get; set; }
    public string FilePath { get; set; } = string.Empty;
}

