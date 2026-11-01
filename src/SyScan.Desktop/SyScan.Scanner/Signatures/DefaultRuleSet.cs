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
                RuleId = "RULE_AUTOCLICKER_SPECIALIZED",
                Name = "Specialized Game AutoClicker Macro Routine",
                Category = RuleCategory.AutoClicker,
                Severity = "Medium",
                Description = "Contains randomized CPS interval generation and synthetic click jitter formulas specific to combat clicking macros.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "RandomCPS",
                    "ClickJitter",
                    "CPSLimit",
                    "BlockHitMacro"
                }
            },
            new DetectionRule
            {
                RuleId = "RULE_MANUAL_MAP_INJECTOR",
                Name = "Reflective PE Loader & Manual Mapper",
                Category = RuleCategory.Injector,
                Severity = "Critical",
                Description = "Matches specific reflective PE injection stubs and manual mapping routines designed to evade API monitoring.",
                TargetGame = "Universal",
                StringPatterns = new List<string>
                {
                    "ReflectiveLoader",
                    "ManualMapInjection",
                    "NtCreateThreadEx_Stub",
                    "QueueUserApc_Injection"
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
                Description = "Matches signatures and resources of known FiveM cheat execution frameworks.",
                TargetGame = "FiveM",
                StringPatterns = new List<string>
                {
                    "eulen.cc",
                    "redengine.eu",
                    "hammafia_loader"
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
                    "wevtutil cl System",
                    "wevtutil cl Security"
                }
            }
        };
    }
}
