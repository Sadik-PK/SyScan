'use client';

import React, { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import Navbar from '@/components/Navbar';
import { listScans, ScanSummary } from '@/lib/api';
import { Search, PlusCircle, RefreshCw, Filter, FileText, Activity } from 'lucide-react';

export default function ScansHistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [gameFilter, setGameFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchScans = async () => {
    try {
      setLoading(true);
      const data = await listScans(1, 100);
      setScans(data);
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      const matchSearch =
        scan.scanId.toLowerCase().includes(search.toLowerCase()) ||
        scan.participantLabel.toLowerCase().includes(search.toLowerCase());
      const matchGame = gameFilter === 'ALL' || scan.gameId.toUpperCase() === gameFilter.toUpperCase();
      const matchStatus = statusFilter === 'ALL' || scan.status.toUpperCase() === statusFilter.toUpperCase();
      return matchSearch && matchGame && matchStatus;
    });
  }, [scans, search, gameFilter, statusFilter]);

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
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Scan Registry</h1>
            <p className="text-sm text-slate-400 mt-1">Audit log and forensic reports archive</p>
          </div>

          <Link
            href="/dashboard/scans/new"
            className="inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm px-4 py-2.5 rounded-xl shadow-lg shadow-blue-600/20 transition-all self-start sm:self-auto"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Create New Scan</span>
          </Link>
        </div>

        {/* Filter Toolbar */}
        <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-4 mb-6 flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by Scan ID or Participant..."
              className="w-full pl-9 pr-4 py-2 bg-[#0b0e14] border border-[#232d42] rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center space-x-3 w-full md:w-auto">
            <div className="flex items-center space-x-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Game:</span>
            </div>
            <select
              value={gameFilter}
              onChange={(e) => setGameFilter(e.target.value)}
              className="bg-[#0b0e14] border border-[#232d42] rounded-xl text-xs px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All Games</option>
              <option value="MINECRAFT">Minecraft</option>
              <option value="FIVEM">FiveM</option>
              <option value="ROBLOX">Roblox</option>
              <option value="R6SIEGE">Rainbow Six</option>
            </select>

            <div className="flex items-center space-x-1.5 text-xs text-slate-400 ml-2">
              <span>Status:</span>
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#0b0e14] border border-[#232d42] rounded-xl text-xs px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="SCANNING">Scanning</option>
              <option value="COMPLETED">Completed</option>
              <option value="CONNECTED">Connected</option>
              <option value="INVITED">Invited</option>
              <option value="CANCELLED">Cancelled</option>
            </select>

            <button
              onClick={fetchScans}
              className="p-2 text-slate-400 hover:text-slate-200 bg-[#0b0e14] border border-[#232d42] rounded-xl"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Scans Table */}
        <div className="bg-[#121722] border border-[#232d42] rounded-2xl overflow-hidden shadow-xl">
          {loading ? (
            <div className="p-16 text-center text-slate-400 text-sm">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-500" />
              <span>Loading registry records...</span>
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="p-16 text-center">
              <p className="text-slate-400 text-sm">No scans match the specified query filters.</p>
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
                    <th className="px-6 py-3 font-semibold">Completed</th>
                    <th className="px-6 py-3 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#232d42]/60">
                  {filteredScans.map((scan) => (
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
                      <td className="px-6 py-4 text-xs font-mono text-slate-400">
                        {scan.completedAt ? new Date(scan.completedAt).toLocaleTimeString() : '—'}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="inline-flex items-center space-x-2">
                          <Link
                            href={`/dashboard/scans/${scan.scanId}`}
                            className="inline-flex items-center space-x-1 text-xs font-medium px-2.5 py-1 rounded bg-[#1f283b] hover:bg-blue-600 hover:text-white text-slate-300 transition-colors"
                          >
                            <Activity className="w-3 h-3" />
                            <span>Monitor</span>
                          </Link>
                          {scan.status === 'Completed' && (
                            <Link
                              href={`/dashboard/scans/${scan.scanId}/report`}
                              className="inline-flex items-center space-x-1 text-xs font-medium px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500 hover:text-white text-emerald-400 transition-colors border border-emerald-500/20"
                            >
                              <FileText className="w-3 h-3" />
                              <span>Report</span>
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

