using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SyScan.Scanner.FileSystem;

public record JarModMetadata(
    string ModId,
    string DisplayName,
    string Version,
    string? Description,
    List<string> Authors,
    string? MainClass,
    string LoaderType, // "Fabric", "Quilt", "Forge", "NeoForge", "StandardJar"
    List<string> Dependencies
);

public record JarAnalysisResult(
    string FilePath,
    string FileName,
    long FileSizeBytes,
    string Sha256Hash,
    bool IsValidZip,
    bool HasManifest,
    string? MainClass,
    string? ImplementationTitle,
    string? ImplementationVersion,
    bool IsJarSigned,
    string? JarSignerCertificate,
    JarModMetadata? MinecraftMod,
    bool IsKnownCheatClient,
    string? KnownClientName,
    string? DetectionReason
);

public static class JarAnalyzer
{
    private const int MaxEntriesToInspect = 10000;
    private const long MaxEntrySizeBytes = 10 * 1024 * 1024; // 10 MB max entry decompressed

    public static JarAnalysisResult AnalyzeJar(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {
            return new JarAnalysisResult(filePath, Path.GetFileName(filePath), 0, string.Empty,
                false, false, null, null, null, false, null, null, false, null, "File does not exist");
        }

        long fileSize = fileInfo.Length;
        string hash = ComputeStreamingSha256(filePath);

        // Verify ZIP magic bytes: PK\x03\x04
        if (!IsValidZipHeader(filePath))
        {
            return new JarAnalysisResult(filePath, fileInfo.Name, fileSize, hash,
                false, false, null, null, null, false, null, null, false, null, "Not a valid ZIP/JAR structure");
        }

        bool hasManifest = false;
        string? mainClass = null;
        string? implTitle = null;
        string? implVersion = null;
        bool isJarSigned = false;
        string? signerCert = null;
        JarModMetadata? modMeta = null;

        var entriesEncountered = new List<string>();

        try
        {
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var archive = new ZipArchive(fileStream, ZipArchiveMode.Read, false);

            int count = 0;
            foreach (var entry in archive.Entries)
            {
                if (++count > MaxEntriesToInspect) break;
                string entryName = entry.FullName.Replace('\\', '/');
                entriesEncountered.Add(entryName);

                // 1. Signature files
                if (entryName.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase))
                {
                    if (entryName.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase) ||
                        entryName.EndsWith(".DSA", StringComparison.OrdinalIgnoreCase) ||
                        entryName.EndsWith(".EC", StringComparison.OrdinalIgnoreCase))
                    {
                        isJarSigned = true;
                        signerCert = Path.GetFileName(entryName);
                    }
                }

                // 2. META-INF/MANIFEST.MF
                if (entryName.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase))
                {
                    hasManifest = true;
                    if (entry.Length <= MaxEntrySizeBytes)
                    {
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        var manifestContent = reader.ReadToEnd();
                        ParseManifest(manifestContent, out var parsedMain, out var parsedTitle, out var parsedVer);
                        mainClass ??= parsedMain;
                        implTitle ??= parsedTitle;
                        implVersion ??= parsedVer;
                    }
                }

                // 3. fabric.mod.json
                if (entryName.Equals("fabric.mod.json", StringComparison.OrdinalIgnoreCase) && modMeta == null)
                {
                    if (entry.Length <= MaxEntrySizeBytes)
                    {
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        string json = reader.ReadToEnd();
                        modMeta = ParseFabricModJson(json);
                    }
                }

                // 4. quilt.mod.json
                if (entryName.Equals("quilt.mod.json", StringComparison.OrdinalIgnoreCase) && modMeta == null)
                {
                    if (entry.Length <= MaxEntrySizeBytes)
                    {
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        string json = reader.ReadToEnd();
                        modMeta = ParseQuiltModJson(json);
                    }
                }

                // 5. META-INF/mods.toml (Forge)
                if (entryName.Equals("META-INF/mods.toml", StringComparison.OrdinalIgnoreCase) && modMeta == null)
                {
                    if (entry.Length <= MaxEntrySizeBytes)
                    {
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        string toml = reader.ReadToEnd();
                        modMeta = ParseForgeModsToml(toml);
                    }
                }

                // 6. mcmod.info (Legacy Forge)
                if (entryName.Equals("mcmod.info", StringComparison.OrdinalIgnoreCase) && modMeta == null)
                {
                    if (entry.Length <= MaxEntrySizeBytes)
                    {
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        string json = reader.ReadToEnd();
                        modMeta = ParseMcmodInfo(json);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            return new JarAnalysisResult(filePath, fileInfo.Name, fileSize, hash,
                true, hasManifest, mainClass, implTitle, implVersion, isJarSigned, signerCert, modMeta,
                false, null, $"Archive inspection error: {ex.Message}");
        }

        // Classify known Minecraft Cheat / Utility Clients
        bool isCheat = false;
        string? clientName = null;
        string? reason = null;

        // Check 1: Fabric/Quilt/Forge Mod ID & Name
        if (modMeta != null)
        {
            string idLower = modMeta.ModId.ToLowerInvariant();
            string nameLower = modMeta.DisplayName.ToLowerInvariant();

            if (idLower == "meteor-client" || nameLower.Contains("meteor client") || idLower.Contains("meteor"))
            {
                isCheat = true;
                clientName = "Meteor Client";
                reason = $"Recognized Meteor Client metadata (Mod ID: '{modMeta.ModId}', Version: '{modMeta.Version}', Loader: {modMeta.LoaderType})";
            }
            else if (idLower == "liquidbounce" || nameLower.Contains("liquidbounce"))
            {
                isCheat = true;
                clientName = "LiquidBounce";
                reason = $"Recognized LiquidBounce cheat client metadata (Mod ID: '{modMeta.ModId}', Version: '{modMeta.Version}')";
            }
            else if (idLower.Contains("aristois") || nameLower.Contains("aristois"))
            {
                isCheat = true;
                clientName = "Aristois";
                reason = $"Recognized Aristois utility/cheat client metadata (Mod ID: '{modMeta.ModId}')";
            }
            else if (idLower.Contains("wurst") || nameLower.Contains("wurst client"))
            {
                isCheat = true;
                clientName = "Wurst Client";
                reason = $"Recognized Wurst cheat client metadata (Mod ID: '{modMeta.ModId}')";
            }
            else if (idLower.Contains("inertia") || nameLower.Contains("inertia"))
            {
                isCheat = true;
                clientName = "Inertia Client";
                reason = $"Recognized Inertia client metadata (Mod ID: '{modMeta.ModId}')";
            }
            else if (idLower.Contains("bleachhack") || nameLower.Contains("bleachhack"))
            {
                isCheat = true;
                clientName = "BleachHack";
                reason = $"Recognized BleachHack client metadata (Mod ID: '{modMeta.ModId}')";
            }
        }

        // Check 2: Package identifiers / Entry names inside archive
        if (!isCheat)
        {
            foreach (var entry in entriesEncountered)
            {
                if (entry.StartsWith("meteordevelopment/meteorclient", StringComparison.OrdinalIgnoreCase))
                {
                    isCheat = true;
                    clientName = "Meteor Client";
                    reason = "Internal package structure matches 'meteordevelopment.meteorclient'";
                    break;
                }
                if (entry.StartsWith("net/ccbluex/liquidbounce", StringComparison.OrdinalIgnoreCase))
                {
                    isCheat = true;
                    clientName = "LiquidBounce";
                    reason = "Internal package structure matches 'net.ccbluex.liquidbounce'";
                    break;
                }
                if (entry.StartsWith("net/wurstclient", StringComparison.OrdinalIgnoreCase))
                {
                    isCheat = true;
                    clientName = "Wurst Client";
                    reason = "Internal package structure matches 'net.wurstclient'";
                    break;
                }
                if (entry.StartsWith("me/deftware/client", StringComparison.OrdinalIgnoreCase))
                {
                    isCheat = true;
                    clientName = "Aristois";
                    reason = "Internal package structure matches 'me.deftware.client'";
                    break;
                }
            }
        }

        // Check 3: Manifest Main-Class / Titles
        if (!isCheat)
        {
            string mainLower = (mainClass ?? string.Empty).ToLowerInvariant();
            string titleLower = (implTitle ?? string.Empty).ToLowerInvariant();

            if (mainLower.Contains("meteorclient") || titleLower.Contains("meteor client"))
            {
                isCheat = true;
                clientName = "Meteor Client";
                reason = $"Manifest declares Meteor Client (Main-Class: '{mainClass}', Title: '{implTitle}')";
            }
            else if (mainLower.Contains("liquidbounce") || titleLower.Contains("liquidbounce"))
            {
                isCheat = true;
                clientName = "LiquidBounce";
                reason = $"Manifest declares LiquidBounce (Main-Class: '{mainClass}')";
            }
            else if (mainLower.Contains("wurstclient") || titleLower.Contains("wurst"))
            {
                isCheat = true;
                clientName = "Wurst Client";
                reason = $"Manifest declares Wurst Client (Main-Class: '{mainClass}')";
            }
        }

        // Check 4: Filename match fallback if uncompressed/obfuscated
        if (!isCheat)
        {
            string fnLower = fileInfo.Name.ToLowerInvariant();
            if (fnLower.Contains("meteor") && (fnLower.Contains("client") || fnLower.Contains("fabric")))
            {
                isCheat = true;
                clientName = "Meteor Client (Suspected)";
                reason = $"Filename '{fileInfo.Name}' matches Meteor Client naming pattern";
            }
        }

        return new JarAnalysisResult(
            filePath,
            fileInfo.Name,
            fileSize,
            hash,
            true,
            hasManifest,
            mainClass,
            implTitle,
            implVersion,
            isJarSigned,
            signerCert,
            modMeta,
            isCheat,
            clientName,
            reason
        );
    }

    private static bool IsValidZipHeader(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < 4) return false;
            byte[] header = new byte[4];
            int read = fs.Read(header, 0, 4);
            return read == 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04;
        }
        catch
        {
            return false;
        }
    }

    private static void ParseManifest(string content, out string? mainClass, out string? title, out string? version)
    {
        mainClass = null;
        title = null;
        version = null;

        using var sr = new StringReader(content);
        string? line;
        while ((line = sr.ReadLine()) != null)
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string key = line[..colon].Trim();
            string val = line[(colon + 1)..].Trim();

            if (key.Equals("Main-Class", StringComparison.OrdinalIgnoreCase)) mainClass = val;
            else if (key.Equals("Implementation-Title", StringComparison.OrdinalIgnoreCase)) title = val;
            else if (key.Equals("Implementation-Version", StringComparison.OrdinalIgnoreCase)) version = val;
            else if (key.Equals("Specification-Title", StringComparison.OrdinalIgnoreCase) && title == null) title = val;
        }
    }

    private static JarModMetadata? ParseFabricModJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string id = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            string name = root.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? id : id;
            string version = root.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? "unknown" : "unknown";
            string? description = root.TryGetProperty("description", out var dProp) ? dProp.GetString() : null;

            var authors = new List<string>();
            if (root.TryGetProperty("authors", out var authProp))
            {
                if (authProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var a in authProp.EnumerateArray())
                    {
                        if (a.ValueKind == JsonValueKind.String) authors.Add(a.GetString()!);
                        else if (a.ValueKind == JsonValueKind.Object && a.TryGetProperty("name", out var n))
                            authors.Add(n.GetString() ?? string.Empty);
                    }
                }
            }

            var deps = new List<string>();
            if (root.TryGetProperty("depends", out var depProp) && depProp.ValueKind == JsonValueKind.Object)
            {
                foreach (var dep in depProp.EnumerateObject())
                {
                    deps.Add($"{dep.Name}: {dep.Value}");
                }
            }

            string? entrypoint = null;
            if (root.TryGetProperty("entrypoints", out var epProp) && epProp.ValueKind == JsonValueKind.Object)
            {
                if (epProp.TryGetProperty("main", out var mainArr))
                {
                    if (mainArr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var m in mainArr.EnumerateArray())
                        {
                            entrypoint = m.GetString();
                            if (entrypoint != null) break;
                        }
                    }
                    else if (mainArr.ValueKind == JsonValueKind.String)
                    {
                        entrypoint = mainArr.GetString();
                    }
                }
            }

            return new JarModMetadata(id, name, version, description, authors, entrypoint, "Fabric", deps);
        }
        catch
        {
            return null;
        }
    }

    private static JarModMetadata? ParseQuiltModJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("quilt_loader", out var ql)) return null;

            string id = ql.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            string version = ql.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? "unknown" : "unknown";
            string name = id;

            if (root.TryGetProperty("metadata", out var meta))
            {
                if (meta.TryGetProperty("name", out var nameProp)) name = nameProp.GetString() ?? id;
            }

            return new JarModMetadata(id, name, version, null, new List<string>(), null, "Quilt", new List<string>());
        }
        catch
        {
            return null;
        }
    }

    private static JarModMetadata? ParseForgeModsToml(string toml)
    {
        try
        {
            string modId = "forge_mod";
            string displayName = "Forge Mod";
            string version = "unknown";

            using var sr = new StringReader(toml);
            string? line;
            while ((line = sr.ReadLine()) != null)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("modId=", StringComparison.OrdinalIgnoreCase))
                {
                    modId = ExtractTomlValue(trimmed);
                }
                else if (trimmed.StartsWith("displayName=", StringComparison.OrdinalIgnoreCase))
                {
                    displayName = ExtractTomlValue(trimmed);
                }
                else if (trimmed.StartsWith("version=", StringComparison.OrdinalIgnoreCase))
                {
                    version = ExtractTomlValue(trimmed);
                }
            }

            return new JarModMetadata(modId, displayName, version, null, new List<string>(), null, "Forge", new List<string>());
        }
        catch
        {
            return null;
        }
    }

    private static string ExtractTomlValue(string line)
    {
        int idx = line.IndexOf('=');
        if (idx < 0) return string.Empty;
        var val = line[(idx + 1)..].Trim();
        return val.Trim('"', '\'');
    }

    private static JarModMetadata? ParseMcmodInfo(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            JsonElement item;

            if (root.ValueKind == JsonValueKind.Array && root.GetArrayLength() > 0)
            {
                item = root[0];
            }
            else if (root.TryGetProperty("modList", out var list) && list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0)
            {
                item = list[0];
            }
            else
            {
                return null;
            }

            string id = item.TryGetProperty("modid", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            string name = item.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? id : id;
            string version = item.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? "unknown" : "unknown";

            return new JarModMetadata(id, name, version, null, new List<string>(), null, "ForgeLegacy", new List<string>());
        }
        catch
        {
            return null;
        }
    }

    public static string ComputeStreamingSha256(string filePath)
    {
        try
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024);
            var hashBytes = sha.ComputeHash(stream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
        catch
        {
            return "hash_unavailable";
        }
    }
}
