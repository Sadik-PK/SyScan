using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.IPC;

public sealed class CollectorIpcServer : IDisposable
{
    private readonly string _pipeName;
    private readonly string _expectedNonce;
    private readonly Func<CollectorRequest, Task<CollectorResponse>> _requestHandler;
    private readonly CancellationTokenSource _cts = new();
    private Task? _serverTask;
    private bool _disposed;

    public CollectorIpcServer(
        string pipeName,
        string expectedNonce,
        Func<CollectorRequest, Task<CollectorResponse>> requestHandler)
    {
        _pipeName = pipeName;
        _expectedNonce = expectedNonce;
        _requestHandler = requestHandler;
    }

    public void Start()
    {
        _serverTask = Task.Run(ListenLoopAsync);
    }

    private async Task ListenLoopAsync()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                // Create pipe with current user security
                server = CreateSecuredServerStream(_pipeName);
                await server.WaitForConnectionAsync(_cts.Token);

                // Handle client connection
                await HandleConnectionAsync(server, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Re-open pipe on transient failure
                await Task.Delay(100, _cts.Token);
            }
            finally
            {
                server?.Dispose();
            }
        }
    }

    private static NamedPipeServerStream CreateSecuredServerStream(string pipeName)
    {
        var pipeSecurity = new PipeSecurity();
        var currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser != null)
        {
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                currentUser,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }

        // Allow administrators
        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            adminSid,
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            65536,
            65536,
            pipeSecurity);
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream stream, CancellationToken ct)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

        while (!ct.IsCancellationRequested && stream.IsConnected)
        {
            int messageLength;
            try
            {
                messageLength = reader.ReadInt32();
            }
            catch
            {
                break; // Client disconnected
            }

            if (messageLength <= 0 || messageLength > 10 * 1024 * 1024)
            {
                // Malformed or dangerous payload length
                break;
            }

            byte[] buffer = reader.ReadBytes(messageLength);
            string json = Encoding.UTF8.GetString(buffer);

            CollectorRequest? request = null;
            try
            {
                request = JsonSerializer.Deserialize<CollectorRequest>(json);
            }
            catch { }

            if (request == null || !string.Equals(request.SessionNonce, _expectedNonce, StringComparison.Ordinal))
            {
                // Nonce mismatch or invalid payload: close connection immediately
                var rejection = new CollectorResponse
                {
                    RequestId = request?.RequestId ?? string.Empty,
                    Success = false,
                    Status = "AccessDenied",
                    ErrorMessage = "Invalid session authentication nonce."
                };
                SendResponse(writer, rejection);
                break;
            }

            CollectorResponse response;
            try
            {
                response = await _requestHandler(request);
            }
            catch (Exception ex)
            {
                response = new CollectorResponse
                {
                    RequestId = request.RequestId,
                    Success = false,
                    Status = "Failed",
                    ErrorMessage = ex.Message
                };
            }

            SendResponse(writer, response);

            if (request.Command == IpcCommands.Shutdown)
            {
                _cts.Cancel();
                break;
            }
        }
    }

    private static void SendResponse(BinaryWriter writer, CollectorResponse response)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(response);
        writer.Write(payload.Length);
        writer.Write(payload);
        writer.Flush();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }
}

