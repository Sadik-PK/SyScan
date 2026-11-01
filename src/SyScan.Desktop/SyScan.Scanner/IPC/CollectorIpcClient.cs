using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.IPC;

public sealed class CollectorIpcClient : IDisposable
{
    private readonly string _pipeName;
    private readonly string _sessionNonce;
    private NamedPipeClientStream? _clientStream;
    private BinaryReader? _reader;
    private BinaryWriter? _writer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    public CollectorIpcClient(string pipeName, string sessionNonce)
    {
        _pipeName = pipeName;
        _sessionNonce = sessionNonce;
    }

    public async Task<bool> ConnectAsync(int timeoutMs = 5000, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (_clientStream != null && _clientStream.IsConnected)
                return true;

            _clientStream?.Dispose();
            _clientStream = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            await _clientStream.ConnectAsync(timeoutMs, ct);
            _reader = new BinaryReader(_clientStream, Encoding.UTF8, leaveOpen: true);
            _writer = new BinaryWriter(_clientStream, Encoding.UTF8, leaveOpen: true);

            // Test connection with Ping
            var pingResponse = await SendRequestInternalAsync(new CollectorRequest
            {
                Command = IpcCommands.Ping,
                SessionNonce = _sessionNonce
            }, ct);

            return pingResponse.Success;
        }
        catch
        {
            return false;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<CollectorResponse> SendRequestAsync(CollectorRequest request, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            return await SendRequestInternalAsync(request, ct);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<CollectorResponse> SendRequestInternalAsync(CollectorRequest request, CancellationToken ct)
    {
        if (_clientStream == null || !_clientStream.IsConnected || _writer == null || _reader == null)
        {
            return new CollectorResponse
            {
                RequestId = request.RequestId,
                Success = false,
                Status = "Disconnected",
                ErrorMessage = "IPC client is not connected to elevated collector."
            };
        }

        request.SessionNonce = _sessionNonce;
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);

        _writer.Write(payload.Length);
        _writer.Write(payload);
        _writer.Flush();

        // Read response length
        int length = _reader.ReadInt32();
        if (length <= 0 || length > 10 * 1024 * 1024)
        {
            return new CollectorResponse
            {
                RequestId = request.RequestId,
                Success = false,
                Status = "ProtocolError",
                ErrorMessage = "Invalid message response length."
            };
        }

        byte[] respBuffer = _reader.ReadBytes(length);
        string json = Encoding.UTF8.GetString(respBuffer);

        var response = JsonSerializer.Deserialize<CollectorResponse>(json);
        return response ?? new CollectorResponse
        {
            RequestId = request.RequestId,
            Success = false,
            Status = "ParseError",
            ErrorMessage = "Could not deserialize collector response."
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _reader?.Dispose();
        _writer?.Dispose();
        _clientStream?.Dispose();
        _lock.Dispose();
    }
}
