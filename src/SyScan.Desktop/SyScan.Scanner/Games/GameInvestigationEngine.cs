using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Games;

public sealed class GameInvestigationEngine
{
    private readonly List<IGameProfile> _profiles = new();

    public GameInvestigationEngine()
    {
        _profiles.Add(new MinecraftProfile());
        _profiles.Add(new FiveMProfile());
        _profiles.Add(new RobloxProfile());
        _profiles.Add(new R6SiegeProfile());
    }

    public void RegisterProfile(IGameProfile profile)
    {
        _profiles.Add(profile);
    }

    public async Task<List<GameInvestigationResult>> RunAllAsync(string? targetGame = null, CancellationToken cancellationToken = default)
    {
        var results = new List<GameInvestigationResult>();

        foreach (var profile in _profiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!string.IsNullOrWhiteSpace(targetGame) &&
                !targetGame.Equals("all", StringComparison.OrdinalIgnoreCase) &&
                !profile.GameId.Equals(targetGame, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                var res = await profile.InvestigateAsync(cancellationToken);
                results.Add(res);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                results.Add(new GameInvestigationResult
                {
                    GameId = profile.GameId,
                    GameName = profile.GameName,
                    GameInstalled = false,
                    Findings = new List<GameFinding>
                    {
                        new GameFinding
                        {
                            RuleId = "GAME_SCAN_ERROR",
                            FindingName = $"Scan error for {profile.GameName}",
                            Description = ex.Message,
                            Severity = "Low",
                            ArtifactType = "Error"
                        }
                    }
                });
            }
        }

        return results;
    }
}

