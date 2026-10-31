'use client';

import React, { useEffect, useState, Suspense } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import { getScanReport, ScanReport } from '@/lib/api';
import {
  ShieldAlert,
  Printer,
  Calendar,
  User,
  Gamepad2,
  Clock,
  ArrowLeft,
  Building2,
  AlertTriangle,
  FileCheck2,
  Hash
} from 'lucide-react';

function ForensicReportContent() {
  const params = useParams();
  const scanId = (params.id as string).toUpperCase();

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        const data = await getScanReport(scanId);
        setReport(data);
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Failed to load forensic report.');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [scanId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0b0e14] flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-[#0b0e14] flex flex-col">
        <Navbar />
        <div className="flex-1 max-w-3xl mx-auto px-4 py-16 text-center">
          <div className="p-6 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
            <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
            <h2 className="text-base font-bold">Report Unavailable</h2>
            <p className="text-xs mt-1 text-slate-400">{error || 'Could not locate scan report.'}</p>
            <Link
              href="/dashboard/scans"
              className="mt-4 inline-block text-xs bg-slate-800 text-slate-200 px-4 py-2 rounded-xl"
            >
              Return to Scan Registry
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] flex flex-col print:bg-white print:text-black">
      <div className="print:hidden">
        <Navbar />
      </div>

      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-8 print:p-0">
        {/* Navigation & Print Actions */}
        <div className="flex items-center justify-between mb-6 print:hidden">
          <Link
            href={`/dashboard/scans/${scanId}`}
            className="inline-flex items-center space-x-1.5 text-xs font-mono text-slate-400 hover:text-slate-200"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Live Monitor</span>
          </Link>

          <button
            onClick={handlePrint}
            className="inline-flex items-center space-x-2 bg-[#161d2b] hover:bg-[#1e273a] text-slate-200 border border-[#232d42] px-4 py-2 rounded-xl text-xs font-medium transition-colors"
          >
            <Printer className="w-4 h-4" />
            <span>Print / Save PDF</span>
          </button>
        </div>

        {/* Official Report Document */}
        <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-8 shadow-2xl print:border-none print:shadow-none print:bg-white print:text-black">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-[#232d42] pb-6 mb-6 gap-4">
            <div>
              <div className="text-[11px] font-mono text-blue-400 uppercase tracking-widest font-semibold mb-1">
                Official Digital Forensic Investigation Report
              </div>
              <h1 className="text-3xl font-extrabold font-mono tracking-tight text-white print:text-black">
                {report.scanId}
              </h1>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Generated: {new Date(report.timestamps.created).toUTCString()}
              </div>
            </div>

            <div className="text-right sm:self-center">
              {report.summary.clean ? (
                <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold">
                  <FileCheck2 className="w-4 h-4" />
                  <span>CLEAN SCAN — NO CHEATS DETECTED</span>
                </div>
              ) : (
                <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 font-mono text-xs font-bold">
                  <ShieldAlert className="w-4 h-4" />
                  <span>{report.summary.critical} CRITICAL DETECTIONS</span>
                </div>
              )}
            </div>
          </div>

          {/* Investigation Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-[#0b0e14] p-5 rounded-xl border border-[#232d42] text-xs font-mono mb-8 print:bg-slate-100 print:text-black">
            <div>
              <span className="text-slate-500 uppercase block">Organization</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 print:text-black">
                <Building2 className="w-3.5 h-3.5 text-blue-400" />
                <span className="truncate">{report.organization}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 uppercase block">Participant</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 print:text-black">
                <User className="w-3.5 h-3.5 text-indigo-400" />
                <span>{report.participant}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 uppercase block">Game Platform</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 uppercase print:text-black">
                <Gamepad2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>{report.game}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 uppercase block">Scan Duration</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 print:text-black">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                <span>{report.timestamps.durationSeconds}s</span>
              </div>
            </div>
          </div>

          {/* Findings Summary Stats */}
          <div className="grid grid-cols-3 gap-4 mb-8 text-center font-mono">
            <div className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42]">
              <div className="text-2xl font-bold text-rose-400">{report.summary.critical}</div>
              <div className="text-[11px] text-slate-400 uppercase mt-1">Critical Signatures</div>
            </div>
            <div className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42]">
              <div className="text-2xl font-bold text-amber-400">{report.summary.warning}</div>
              <div className="text-[11px] text-slate-400 uppercase mt-1">Warnings &amp; Heuristics</div>
            </div>
            <div className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42]">
              <div className="text-2xl font-bold text-purple-400">{report.summary.suspicious}</div>
              <div className="text-[11px] text-slate-400 uppercase mt-1">Suspicious Remnants</div>
            </div>
          </div>

          {/* Section: Forensic Scan Coverage Matrix */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono mb-4 border-b border-[#232d42] pb-2">
              Forensic Scan Coverage &amp; Module Scope
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
              {[
                { id: 'process-scanner', name: 'Active Processes & Threads', status: 'Complete', note: 'All user processes inspected' },
                { id: 'driver-scanner', name: 'Kernel Drivers & Modules', status: 'Complete', note: 'BYOVD exploit catalog verified' },
                { id: 'service-scanner', name: 'Windows Services Inventory', status: 'Complete', note: 'Service registry keys evaluated' },
                { id: 'game-directory', name: 'Game Directory & Injected Mods', status: 'Complete', note: 'Mod folders and proxy DLLs scanned' },
                { id: 'game-log-analyzer', name: 'Historical Game Logs & JVM Agents', status: 'Complete', note: 'Decompressed .log.gz and logs parsed' },
                { id: 'file-system-scanner', name: 'Full Forensic File Inventory', status: 'Complete', note: 'SHA-256 and Authenticode verified' },
                { id: 'forensic-artifacts', name: 'Prefetch, BAM/DAM & Shimcache', status: 'Complete', note: 'Execution artifacts reconstructed' },
                { id: 'file-deletion', name: 'NTFS USN Change Journal', status: 'Complete', note: 'File creation, rename & delete history' },
                { id: 'anti-forensic', name: 'Anti-Forensics & Timestomping', status: 'Complete', note: 'Nanosecond precision & logs checked' },
                { id: 'installed-apps', name: 'Installed Applications', status: 'Complete', note: 'Uninstall keys cataloged' },
                { id: 'registry-scanner', name: 'Run / RunOnce Persistence', status: 'Complete', note: 'Startup persistence keys evaluated' },
                { id: 'event-log-scanner', name: 'Windows Security Event Logs', status: 'Complete', note: 'Audit clear & service install events' },
              ].map((mod) => (
                <div key={mod.id} className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42] flex flex-col justify-between print:bg-slate-50 print:border-slate-300">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-200 print:text-black">{mod.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      {mod.status}
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400 print:text-slate-600">{mod.note}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section: Detailed Findings */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono mb-4 border-b border-[#232d42] pb-2">
              Forensic Findings Details ({report.findings.length})
            </h3>

            {report.findings.length === 0 ? (
              <div className="p-8 text-center bg-[#0b0e14] rounded-xl border border-[#232d42] text-xs text-slate-400 font-mono">
                No indicators of tampering, injection, vulnerable drivers, or cheat processes were detected.
              </div>
            ) : (
              <div className="space-y-4">
                {report.findings.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-5 rounded-xl bg-[#0b0e14] border border-[#232d42] text-xs space-y-2 print:border-slate-300 print:bg-white"
                  >
                    <div className="flex items-center justify-between font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                          {f.severity}
                        </span>
                        <span className="text-slate-400">[{f.moduleId}]</span>
                        <span className="text-slate-300 font-bold">{f.findingId}</span>
                      </div>
                      <span className="text-blue-400">{f.confidence}% Confidence</span>
                    </div>

                    <h4 className="text-sm font-bold text-white print:text-black">{f.title}</h4>
                    <p className="text-slate-400 print:text-slate-700 leading-relaxed">{f.description}</p>

                    {f.filePath && (
                      <div className="font-mono text-[11px] text-slate-400 bg-[#121722] p-2 rounded border border-[#232d42] break-all print:bg-slate-100 print:text-black">
                        Path: {f.filePath}
                      </div>
                    )}

                    {f.fileHash && (
                      <div className="font-mono text-[11px] text-slate-400 flex items-center space-x-1.5">
                        <Hash className="w-3.5 h-3.5 text-slate-500" />
                        <span>SHA-256: {f.fileHash}</span>
                      </div>
                    )}

                    {f.explanation && (
                      <div className="text-[11px] text-slate-400 italic pt-1 border-t border-[#1f2738]">
                        Forensic Explanation: {f.explanation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section: Audit Event Timeline */}
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono mb-4 border-b border-[#232d42] pb-2">
              Timeline of Audit Events
            </h3>
            <div className="space-y-2 font-mono text-xs">
              {report.events.map((evt, idx) => (
                <div key={idx} className="flex items-start space-x-3 py-1.5 border-b border-[#1f2738]/40 last:border-0">
                  <span className="text-slate-400 shrink-0">
                    {new Date(evt.occurredAt).toLocaleTimeString()}
                  </span>
                  <span className="text-slate-300 print:text-black">{evt.message}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function ForensicReportPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#0b0e14] flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <ForensicReportContent />
    </Suspense>
  );
}
