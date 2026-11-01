using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using SyScan.Scanner.Historical;
using SyScan.Scanner.IPC;
using SyScan.Scanner.Recon;
using Xunit;

namespace SyScan.Tests;

public class ElevationAndIpcTests
{
    [Fact]
    public void SystemReconnaissance_CollectsDrivesAndOsMetadata()
    {
        var recon = SystemReconnaissance.Collect();

        Assert.NotNull(recon);
        Assert.NotEmpty(recon.OsVersion);
        Assert.NotEmpty(recon.Architecture);
        Assert.NotEmpty(recon.CurrentUserName);
        Assert.NotEmpty(recon.Drives);
        Assert.True(recon.BootTimeUtc < DateTime.UtcNow);
    }

    [Fact]
    public void SrumParser_HandlesMissingOrPresentSrumDbSafely()
    {
        // Test with non-existent database
        string fakePath = Path.Combine(Path.GetTempPath(), $"fake_srum_{Guid.NewGuid():N}.dat");
        var result = SrumParser.Analyze(fakePath);

        Assert.False(result.SrumDatabaseAccessible);
        Assert.Contains("not present", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CollectorIpc_EndToEnd_CommunicationAndNonceHandshake()
    {
        string nonce = Guid.NewGuid().ToString("N");
        string pipeName = $"SyScan_TestPipe_{nonce}";

        using var server = new CollectorIpcServer(pipeName, nonce, req =>
        {
            if (req.Command == IpcCommands.Ping)
            {
                return Task.FromResult(new CollectorResponse
                {
                    RequestId = req.RequestId,
                    Success = true,
                    IsElevated = true,
                    Status = "Pong"
                });
            }

            return Task.FromResult(new CollectorResponse
            {
                RequestId = req.RequestId,
                Success = false,
                Status = "Unknown"
            });
        });

        server.Start();

        using var client = new CollectorIpcClient(pipeName, nonce);
        bool connected = await client.ConnectAsync(timeoutMs: 3000);
        Assert.True(connected);

        // Test valid command
        var response = await client.SendRequestAsync(new CollectorRequest
        {
            Command = IpcCommands.Ping,
            SessionNonce = nonce
        });

        Assert.True(response.Success);
        Assert.Equal("Pong", response.Status);
        Assert.True(response.IsElevated);

        // Test invalid nonce rejection
        using var rogueClient = new CollectorIpcClient(pipeName, "INVALID_NONCE_ATTACK");
        // Connecting with invalid nonce should fail Ping or be rejected
        var rogueResponse = await rogueClient.SendRequestAsync(new CollectorRequest
        {
            Command = IpcCommands.Ping,
            SessionNonce = "INVALID_NONCE_ATTACK"
        });

        Assert.False(rogueResponse.Success);
    }
}
