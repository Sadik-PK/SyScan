'use client';

import React, { useEffect, useState, useRef, Suspense } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import { getScan, cancelScan, ScanDetail, ScanEvent, ScanFinding } from '@/lib/api';
import { ScanHubClient } from '@/lib/signalr';
import {
  ShieldAlert,
  Activity,
  CheckCircle2,
  AlertTriangle,
  StopCircle,
  FileText,
  User,
  Gamepad2,
  Calendar,
  Layers,
  ArrowUpRight
} from 'lucide-react';

function ActiveScanMonitorContent() {
  const params = useParams();
  const scanId = (params.id as string).toUpperCase();

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  // Live state
  const [status, setStatus] = useState<string>('Loading');
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [currentModule, setCurrentModule] = useState<string>('Initializing');
  const [moduleProgress, setModuleProgress] = useState<number>(0);

  const hubClientRef = useRef<ScanHubClient | null>(null);
  const timelineEndRef = useRef<HTMLDivElement>(null);

  // Fetch initial scan state
  const fetchScan = async () => {
    try {
      setLoading(true);
      const data = await getScan(scanId);
      setScan(data);
      setStatus(data.status);
      setEvents(data.events || []);
      setFindings(data.findings || []);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to load scan details.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();

    // Start SignalR live connection
    const hub = new ScanHubClient(scanId, {
      onScanEvent: (evt) => {
        setEvents((prev) => [
          ...prev,
          {
            eventType: evt.eventType,
            message: evt.message,
            moduleId: evt.payload ? (evt.payload as { moduleId?: string }).moduleId : undefined,
            occurredAt: evt.occurredAt,
          },
        ]);
        if (evt.eventType === 'ModuleStarted') {
          const mod = (evt.payload as { moduleId?: string })?.moduleId;
          if (mod) setCurrentModule(mod);
        }
      },
      onStatusChanged: (data) => {
        setStatus(data.status);
      },
      onNewFinding: (data) => {
        const f = data.finding as unknown as ScanFinding;
        setFindings((prev) => {
          if (prev.some((existing) => existing.findingId === f.findingId)) return prev;
          return [f, ...prev];
        });
      },
      onModuleProgress: (data) => {
        setCurrentModule(data.moduleId);
        setModuleProgress(data.progressPercent);
      },
    });

    hub.start();
    hubClientRef.current = hub;

    return () => {
      hub.stop();
    };
  }, [scanId]);

  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const handleCancelScan = async () => {
    if (!confirm('Are you sure you want to cancel this forensic scan?')) return;
    try {
      setCancelling(true);
      await cancelScan(scanId);
      setStatus('Cancelled');
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to cancel scan.');
    } finally {
      setCancelling(false);
    }
  };

  const getStatusBadge = (st: string) => {
    switch (st) {
      case 'Scanning':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
            <span>Scanning Active</span>
          </span>
        );
      case 'Completed':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Investigation Completed</span>
          </span>
        );
      case 'Connected':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Activity className="w-3.5 h-3.5" />
            <span>Desktop Connected</span>
          </span>
        );
      case 'AwaitingConsent':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <span>Awaiting Participant Approval</span>
          </span>
        );
      case 'Cancelled':
      case 'Declined':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <span>{st}</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <span>{st}</span>
          </span>
        );
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
            CRITICAL
          </span>
        );
      case 'Warning':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
            WARNING
          </span>
        );
      case 'Suspicious':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">
            SUSPICIOUS
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
            INFO
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
          <div>
            <div className="flex items-center space-x-3 mb-1">
              <Link
                href="/dashboard/scans"
                className="text-xs font-mono text-slate-500 hover:text-slate-300 transition-colors"
              >
                Scans
              </Link>
              <span className="text-slate-600">/</span>
              <span className="text-xs font-mono text-slate-400">{scanId}</span>
            </div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold tracking-tight text-white font-mono">{scanId}</h1>
              {getStatusBadge(status)}
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {status === 'Completed' && (
              <Link
                href={`/dashboard/scans/${scanId}/report`}
                className="inline-flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs px-4 py-2.5 rounded-xl shadow-lg shadow-emerald-600/20 transition-all"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>View Full Forensic Report</span>
              </Link>
            )}

            {['Connected', 'Scanning', 'AwaitingConsent', 'Invited'].includes(status) && (
              <button
                onClick={handleCancelScan}
                disabled={cancelling}
                className="inline-flex items-center space-x-1.5 bg-[#1a1f2c] hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 font-medium text-xs px-3.5 py-2 rounded-xl transition-colors disabled:opacity-50"
              >
                <StopCircle className="w-3.5 h-3.5" />
                <span>{cancelling ? 'Cancelling...' : 'Cancel Scan'}</span>
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Metadata Summary Banner */}
        {scan && (
          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-4 mb-6 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 block uppercase">Participant</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5">
                <User className="w-3.5 h-3.5 text-blue-400" />
                <span>{scan.participantLabel}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 block uppercase">Game Platform</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 uppercase">
                <Gamepad2 className="w-3.5 h-3.5 text-indigo-400" />
                <span>{scan.gameId}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 block uppercase">Created At</span>
              <div className="text-slate-200 flex items-center space-x-1 mt-0.5">
                <Calendar className="w-3.5 h-3.5 text-slate-400" />
                <span>{new Date(scan.createdAt).toLocaleTimeString()}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 block uppercase">Live Findings</span>
              <div className="text-rose-400 font-bold flex items-center space-x-1 mt-0.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{findings.length} Flagged</span>
              </div>
            </div>
          </div>
        )}

        {/* Progress Bar (when scanning) */}
        {status === 'Scanning' && (
          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-4 mb-6">
            <div className="flex items-center justify-between text-xs font-mono mb-2">
              <div className="flex items-center space-x-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <span className="text-slate-300 font-semibold">Executing: {currentModule}</span>
              </div>
              <span className="text-blue-400 font-bold">{moduleProgress}%</span>
            </div>
            <div className="w-full bg-[#0b0e14] rounded-full h-2 overflow-hidden border border-[#232d42]">
              <div
                className="bg-gradient-to-r from-blue-600 to-indigo-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${Math.max(moduleProgress, 5)}%` }}
              />
            </div>
          </div>
        )}

        {/* Two-Column Monitor Grid: Live Findings (Left) & Real-time Timeline (Right) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Findings (8 cols) */}
          <div className="lg:col-span-7 bg-[#121722] border border-[#232d42] rounded-2xl p-5 shadow-xl flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-[#232d42] mb-4">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <h2 className="text-sm font-semibold text-slate-200">Live Detections &amp; Artifacts</h2>
              </div>
              <span className="text-xs font-mono text-slate-500">{findings.length} findings</span>
            </div>

            {findings.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
                <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-3">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <h3 className="text-sm font-semibold text-slate-300">No Malicious Indicators Detected Yet</h3>
                <p className="text-xs text-slate-500 mt-1 max-w-xs">
                  {status === 'Scanning'
                    ? 'Scanner is evaluating system memory, registry keys, and event traces...'
                    : 'System scanned clean with no cheat signatures flagged.'}
                </p>
              </div>
            ) : (
              <div className="space-y-3 overflow-y-auto max-h-[500px] pr-1">
                {findings.map((f, idx) => (
                  <div
                    key={f.findingId || idx}
                    className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42] hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="flex items-center space-x-2">
                        {getSeverityBadge(f.severity)}
                        <span className="text-xs font-mono text-slate-500">[{f.moduleId}]</span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        {f.confidence}% confidence
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-100">{f.title}</h4>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{f.description}</p>

                    {f.filePath && (
                      <div className="mt-2 text-[11px] font-mono text-slate-400 bg-[#121722] px-2.5 py-1.5 rounded border border-[#232d42] break-all">
                        Path: {f.filePath}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Real-time Event Timeline (5 cols) */}
          <div className="lg:col-span-5 bg-[#121722] border border-[#232d42] rounded-2xl p-5 shadow-xl flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-[#232d42] mb-4">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-slate-200">Investigation Timeline</h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                LIVE SIGNALR
              </span>
            </div>

            <div className="space-y-3 overflow-y-auto max-h-[500px] pr-1 font-mono text-xs flex-1">
              {events.length === 0 ? (
                <div className="text-center p-8 text-slate-500 text-xs">Awaiting scanner events...</div>
              ) : (
                events.map((evt, idx) => (
                  <div key={idx} className="flex items-start space-x-2.5 pb-2.5 border-b border-[#1f2738]/50 last:border-0">
                    <span className="text-[11px] text-slate-400 shrink-0 mt-0.5">
                      {new Date(evt.occurredAt).toLocaleTimeString()}
                    </span>
                    <div className="flex-1">
                      <span className="text-slate-300 leading-snug block">{evt.message}</span>
                      {evt.moduleId && (
                        <span className="text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20 inline-block mt-1">
                          {evt.moduleId}
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
              <div ref={timelineEndRef} />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function ActiveScanMonitorPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#0b0e14] flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <ActiveScanMonitorContent />
    </Suspense>
  );
}
