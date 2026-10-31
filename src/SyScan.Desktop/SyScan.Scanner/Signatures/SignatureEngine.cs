using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Signatures;

public sealed class SignatureEngine
{
    private readonly List<DetectionRule> _rules = new();

    public SignatureEngine()
    {
        _rules.AddRange(DefaultRuleSet.GetBuiltInRules());
    }

    public void AddRule(DetectionRule rule)
    {
        _rules.Add(rule);
    }

    public List<SignatureMatchResult> ScanBuffer(byte[] buffer, string sourcePath = "")
    {
        var matches = new List<SignatureMatchResult>();
        if (buffer == null || buffer.Length == 0)
            return matches;

        // Hash check
        string sha256 = ComputeSha256(buffer);

        // Convert buffer to ASCII string and lowercase for fast string pattern matching
        string asciiContent = Encoding.ASCII.GetString(buffer);

        foreach (var rule in _rules)
        {
            if (rule.TargetSha256Hashes.Contains(sha256))
            {
                matches.Add(new SignatureMatchResult
                {
                    RuleId = rule.RuleId,
                    RuleName = rule.Name,
                    Category = rule.Category,
                    Severity = rule.Severity,
                    Description = rule.Description,
                    MatchedPattern = $"SHA256 Match: {sha256}",
                    FilePath = sourcePath,
                    MatchOffset = 0
                });
                continue;
            }

            // String patterns
            if (rule.StringPatterns.Count > 0)
            {
                int matchedCount = 0;
                string lastPattern = string.Empty;
                int firstOffset = -1;

                foreach (var pattern in rule.StringPatterns)
                {
                    int idx = asciiContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        matchedCount++;
                        lastPattern = pattern;
                        if (firstOffset == -1 || idx < firstOffset)
                        {
                            firstOffset = idx;
                        }
                    }
                }

                // If at least 2 patterns match (or 1 if rule only has 1 pattern)
                int threshold = Math.Min(2, rule.StringPatterns.Count);
                if (matchedCount >= threshold)
                {
                    matches.Add(new SignatureMatchResult
                    {
                        RuleId = rule.RuleId,
                        RuleName = rule.Name,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        Description = rule.Description,
                        MatchedPattern = $"{matchedCount}/{rule.StringPatterns.Count} strings matched (e.g. '{lastPattern}')",
                        FilePath = sourcePath,
                        MatchOffset = firstOffset
                    });
                }
            }

            // Byte patterns
            foreach (var bp in rule.BytePatterns)
            {
                int offset = FindBytePattern(buffer, bp.Pattern);
                if (offset >= 0)
                {
                    matches.Add(new SignatureMatchResult
                    {
                        RuleId = rule.RuleId,
                        RuleName = rule.Name,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        Description = rule.Description,
                        MatchedPattern = $"Byte Pattern: {bp.Description}",
                        FilePath = sourcePath,
                        MatchOffset = offset
                    });
                    break;
                }
            }
        }

        return matches;
    }

    public async Task<List<SignatureMatchResult>> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
            return new List<SignatureMatchResult>();

        try
        {
            var info = new FileInfo(filePath);
            // Limit scanning to files under 50MB for signatures
            if (info.Length > 50 * 1024 * 1024)
                return new List<SignatureMatchResult>();

            byte[] bytes = await File.ReadAllBytesAsync(filePath, cancellationToken);
            return ScanBuffer(bytes, filePath);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return new List<SignatureMatchResult>();
        }
    }

    private static int FindBytePattern(byte[] source, byte?[] pattern)
    {
        if (pattern.Length == 0 || source.Length < pattern.Length)
            return -1;

        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int p = 0; p < pattern.Length; p++)
            {
                if (pattern[p].HasValue && pattern[p]!.Value != source[i + p])
                {
                    match = false;
                    break;
                }
            }

            if (match) return i;
        }

        return -1;
    }

    private static string ComputeSha256(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Convert.ToHexStringLower(hash);
    }
}

