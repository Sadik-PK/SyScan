// SignalR Real-time Connection Manager for SyScan
import * as signalR from '@microsoft/signalr';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export interface ScanLiveCallbacks {
  onScanEvent?: (event: { scanId: string; eventType: string; message: string; payload?: unknown; occurredAt: string }) => void;
  onStatusChanged?: (data: { scanId: string; status: string; occurredAt: string }) => void;
  onNewFinding?: (data: { scanId: string; finding: Record<string, unknown> }) => void;
  onModuleProgress?: (data: { scanId: string; moduleId: string; status: string; progressPercent: number; occurredAt: string }) => void;
}

export class ScanHubClient {
  private connection: signalR.HubConnection | null = null;
  private scanId: string;
  private callbacks: ScanLiveCallbacks;

  constructor(scanId: string, callbacks: ScanLiveCallbacks) {
    this.scanId = scanId;
    this.callbacks = callbacks;
  }

  public async start(): Promise<void> {
    const token = typeof window !== 'undefined' ? localStorage.getItem('syscan_token') : null;

    this.connection = new signalR.HubConnectionBuilder()
      .withUrl(`${API_BASE_URL}/hubs/scan`, {
        accessTokenFactory: () => token || '',
        transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.LongPolling,
      })
      .withAutomaticReconnect([0, 2000, 5000, 10000])
      .configureLogging(signalR.LogLevel.Warning)
      .build();

    if (this.callbacks.onScanEvent) {
      this.connection.on('ScanEvent', this.callbacks.onScanEvent);
    }
    if (this.callbacks.onStatusChanged) {
      this.connection.on('StatusChanged', this.callbacks.onStatusChanged);
    }
    if (this.callbacks.onNewFinding) {
      this.connection.on('NewFinding', this.callbacks.onNewFinding);
    }
    if (this.callbacks.onModuleProgress) {
      this.connection.on('ModuleProgress', this.callbacks.onModuleProgress);
    }

    try {
      await this.connection.start();
      await this.connection.invoke('JoinScanGroup', this.scanId);
    } catch (err) {
      console.warn('SignalR initial connection warning:', err);
    }
  }

  public async stop(): Promise<void> {
    if (this.connection) {
      try {
        await this.connection.invoke('LeaveScanGroup', this.scanId);
        await this.connection.stop();
      } catch {
        // Safe disposal
      }
      this.connection = null;
    }
  }
}

