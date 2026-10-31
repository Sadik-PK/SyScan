'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import Navbar from '@/components/Navbar';
import { listScans, ScanSummary } from '@/lib/api';
import {
  ShieldAlert,
  Search,
  PlusCircle,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Gamepad2
} from 'lucide-react';

export default function DashboardOverviewPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await listScans(1, 20);
      setScans(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to fetch scans.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/login');
    } else if (isAuthenticated) {
      fetchScans();
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0b0e14] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const totalScans = scans.length;
  const activeScans = scans.filter((s) => ['Connected', 'Scanning', 'AwaitingConsent', 'Invited'].includes(s.status)).length;
  const completedScans = scans.filter((s) => s.status === 'Completed').length;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Scanning':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
            Scanning
          </span>
        );
      case 'Completed':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            Completed
          </span>
        );
      case 'Connected':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            Connected
          </span>
        );
      case 'Invited':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            Invited
          </span>
        );
      case 'Cancelled':
      case 'Declined':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            {status}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Top title & action */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Forensic Operations</h1>
            <p className="text-sm text-slate-400 mt-1">Real-time scan monitoring and evidence review</p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={fetchScans}
              className="p-2 text-slate-400 hover:text-slate-200 bg-[#161d2b] border border-[#232d42] rounded-xl hover:bg-[#1f283b] transition-colors"
              title="Refresh Scans"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <Link
              href="/dashboard/scans/new"
              className="inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm px-4 py-2.5 rounded-xl shadow-lg shadow-blue-600/20 transition-all"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Create New Scan</span>
            </Link>
          </div>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Total Scans</span>
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400">
                <Search className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3 text-3xl font-bold font-mono text-white">{totalScans}</div>
            <div className="mt-1 text-xs text-slate-500 font-mono">Recorded in database</div>
          </div>

          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Active Scans</span>
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400">
                <Clock className="w-4 h-4 animate-spin" />
              </div>
            </div>
            <div className="mt-3 text-3xl font-bold font-mono text-cyan-400">{activeScans}</div>
            <div className="mt-1 text-xs text-slate-500 font-mono">In progress or awaiting pair</div>
          </div>

          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Completed</span>
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3 text-3xl font-bold font-mono text-emerald-400">{completedScans}</div>
            <div className="mt-1 text-xs text-slate-500 font-mono">With finalized forensic reports</div>
          </div>

          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Investigation Rule Engine</span>
              <div className="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400">
                <ShieldAlert className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3 text-3xl font-bold font-mono text-indigo-400">12</div>
            <div className="mt-1 text-xs text-slate-500 font-mono">Collection modules active</div>
          </div>
        </div>

        {/* Recent Scans Table */}
        <div className="bg-[#121722] border border-[#232d42] rounded-2xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-[#232d42] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-semibold text-slate-200">Recent Forensic Scans</h2>
              <span className="text-xs font-mono text-slate-400">({scans.length})</span>
            </div>
            <Link
              href="/dashboard/scans"
              className="text-xs font-semibold text-blue-400 hover:text-blue-300 inline-flex items-center space-x-1"
            >
              <span>View All History</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {error && (
            <div className="p-4 bg-rose-500/10 border-b border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div className="p-12 text-center text-slate-400 text-sm">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-500" />
              <span>Loading scans...</span>
            </div>
          ) : scans.length === 0 ? (
            <div className="p-16 text-center">
              <Gamepad2 className="w-12 h-12 mx-auto text-slate-600 mb-3" />
              <h3 className="text-base font-semibold text-slate-300">No Scans Recorded</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                Generate a unique scan invitation for a player or participant to initiate PC forensic analysis.
              </p>
              <Link
                href="/dashboard/scans/new"
                className="mt-4 inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs px-3.5 py-2 rounded-lg transition-colors"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>Create First Scan</span>
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-[#0e131d] text-[11px] font-mono text-slate-400 uppercase border-b border-[#232d42]">
                  <tr>
                    <th className="px-6 py-3 font-semibold">Scan ID</th>
                    <th className="px-6 py-3 font-semibold">Participant</th>
                    <th className="px-6 py-3 font-semibold">Game</th>
                    <th className="px-6 py-3 font-semibold">Status</th>
                    <th className="px-6 py-3 font-semibold">Created</th>
                    <th className="px-6 py-3 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#232d42]/60 font-sans">
                  {scans.slice(0, 10).map((scan) => (
                    <tr key={scan.scanId} className="hover:bg-[#161d2b]/60 transition-colors">
                      <td className="px-6 py-4 font-mono font-semibold text-blue-400">
                        <Link href={`/dashboard/scans/${scan.scanId}`} className="hover:underline">
                          {scan.scanId}
                        </Link>
                      </td>
                      <td className="px-6 py-4 font-medium text-slate-200">{scan.participantLabel}</td>
                      <td className="px-6 py-4 text-xs font-mono uppercase text-slate-400">{scan.gameId}</td>
                      <td className="px-6 py-4">{getStatusBadge(scan.status)}</td>
                      <td className="px-6 py-4 text-xs font-mono text-slate-400">
                        {new Date(scan.createdAt).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="inline-flex items-center space-x-2">
                          <Link
                            href={`/dashboard/scans/${scan.scanId}`}
                            className="text-xs font-medium px-2.5 py-1 rounded bg-[#1f283b] hover:bg-blue-600 hover:text-white text-slate-300 transition-colors"
                          >
                            Live Monitor
                          </Link>
                          {scan.status === 'Completed' && (
                            <Link
                              href={`/dashboard/scans/${scan.scanId}/report`}
                              className="text-xs font-medium px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500 hover:text-white text-emerald-400 transition-colors border border-emerald-500/20"
                            >
                              Report
                            </Link>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

