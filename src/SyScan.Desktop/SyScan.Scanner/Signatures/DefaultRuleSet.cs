using System;
using System.Collections.Generic;

namespace SyScan.Scanner.Signatures;

public static class DefaultRuleSet
{
    public static List<DetectionRule> GetBuiltInRules()
    {
        return new List<DetectionRule>
        {
            new DetectionRule
            {
                RuleId = "RULE_AUTOCLICKER_GENERIC",
                Name = "Generic High-Frequency AutoClicker",
                Category = RuleCategory.AutoClicker,
                Severity = "High",
                Description = "Contains mouse_event / SendInput loops with millisecond sleep delays typical of combat auto-clickers.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "MOUSEEVENTF_LEFTDOWN",
                    "MOUSEEVENTF_LEFTUP",
                    "CPS",
                    "Jitter"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_DLL_INJECTOR_WIN32",
                Name = "Standard Win32 Process Injector",
                Category = RuleCategory.Injector,
                Severity = "Critical",
                Description = "Contains Win32 memory allocation and remote thread execution APIs used for DLL injection.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "LoadLibraryA"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_MANUAL_MAP_INJECTOR",
                Name = "Manual Map / Reflective PE Loader",
                Category = RuleCategory.Injector,
                Severity = "Critical",
                Description = "Detects strings indicative of manual PE mapping to bypass standard LoadLibrary anticheat hooks.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "ReflectiveLoader",
                    "ManualMap",
                    "NtCreateThreadEx",
                    "NtWriteVirtualMemory"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_MINECRAFT_CHEAT_LOADER",
                Name = "Minecraft Injection Client Signatures",
                Category = RuleCategory.CheatLoader,
                Severity = "Critical",
                Description = "Matches domain strings or signatures of popular Minecraft injection clients (Vape, Drip).",
                TargetGame = "Minecraft",
                StringPatterns = new List<string>
                {
                    "vape.gg",
                    "drip.gg",
                    "vape_v4",
                    "DripLite"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_FIVEM_EXECUTOR",
                Name = "FiveM Lua / Native Cheat Executor",
                Category = RuleCategory.CheatLoader,
                Severity = "Critical",
                Description = "Matches signatures and resources of popular FiveM execution frameworks.",
                TargetGame = "FiveM",
                StringPatterns = new List<string>
                {
                    "eulen.cc",
                    "redengine.eu",
                    "hammafia",
                    "CitizenFX.Core.Native"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_ANTIFORENSIC_CLEANER",
                Name = "Anti-Forensic Cleaner / Evidence Eraser",
                Category = RuleCategory.AntiForensicTool,
                Severity = "Critical",
                Description = "Matches commands and code designed to clear USN Journal, event logs, or Prefetch files.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "fsutil usn deletejournal",
                    "wevtutil cl",
                    "Clear-EventLog",
                    "Stop-Service EventLog"
                }
            }
        };
    }
}

