'use client';

import React, { useEffect, useState, Suspense } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import {
  getScanReport,
  getScanInventory,
  getScanInventoryCsvUrl,
  ScanReport,
  FileInventoryItem,
  FileInventoryResponse
} from '@/lib/api';
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
  Hash,
  Download,
  Search,
  Filter,
  FileCode,
  Layers,
  ShieldCheck,
  CheckCircle2,
  Info,
  ChevronLeft,
  ChevronRight,
  FileBox
} from 'lucide-react';

function ForensicReportContent() {
  const params = useParams();
  const scanId = (params.id as string).toUpperCase();

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // File Inventory State
  const [activeTab, setActiveTab] = useState<'ALL' | 'EXE' | 'JAR' | 'DLL' | 'SYS' | 'OTHER' | 'HISTORICAL'>('ALL');
  const [inventory, setInventory] = useState<FileInventoryResponse | null>(null);
  const [invLoading, setInvLoading] = useState(false);
  const [invPage, setInvPage] = useState(1);
  const [invSearch, setInvSearch] = useState('');
  const [invGameFilter, setInvGameFilter] = useState('');
  const [invStatusFilter, setInvStatusFilter] = useState('');
  const [selectedFileDetail, setSelectedFileDetail] = useState<FileInventoryItem | null>(null);

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

  // Load Inventory when tab, search, or filters change
  useEffect(() => {
    const fetchInventory = async () => {
      try {
        setInvLoading(true);
        const extFilter = activeTab === 'EXE' ? '.exe'
          : activeTab === 'JAR' ? '.jar'
          : activeTab === 'DLL' ? '.dll'
          : activeTab === 'SYS' ? '.sys'
          : undefined;

        const data = await getScanInventory(scanId, {
          extension: extFilter,
          game: invGameFilter || undefined,
          status: invStatusFilter || undefined,
          search: invSearch || undefined,
          page: invPage,
          pageSize: 25
        });
        setInventory(data);
      } catch {
        // Fallback gracefully
      } finally {
        setInvLoading(false);
      }
    };

    if (scanId) {
      fetchInventory();
    }
  }, [scanId, activeTab, invPage, invSearch, invGameFilter, invStatusFilter]);

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

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const exportInventoryJson = () => {
    if (!inventory) return;
    const jsonStr = JSON.stringify(inventory.items, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${scanId}_FileInventory.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const invSummary = inventory?.summary || {
    totalFiles: report.fileInventorySummary?.totalDiscovered || 0,
    totalExe: report.fileInventorySummary?.totalExe || 0,
    totalJar: report.fileInventorySummary?.totalJar || 0,
    totalDll: report.fileInventorySummary?.totalDll || 0,
    totalSys: report.fileInventorySummary?.totalSys || 0,
    totalSigned: report.fileInventorySummary?.totalSigned || 0,
    totalUnsigned: report.fileInventorySummary?.totalUnsigned || 0,
    totalHashed: report.fileInventorySummary?.totalHashed || 0,
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] flex flex-col print:bg-white print:text-black">
      <div className="print:hidden">
        <Navbar />
      </div>

      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-8 print:p-0">
        {/* Navigation & Print Actions */}
        <div className="flex items-center justify-between mb-6 print:hidden">
          <Link
            href={`/dashboard/scans/${scanId}`}
            className="inline-flex items-center space-x-1.5 text-xs font-mono text-slate-400 hover:text-slate-200"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Live Monitor</span>
          </Link>

          <div className="flex items-center space-x-2">
            <a
              href={getScanInventoryCsvUrl(scanId)}
              className="inline-flex items-center space-x-1.5 bg-[#161d2b] hover:bg-[#1e273a] text-slate-200 border border-[#232d42] px-3.5 py-2 rounded-xl text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span>Export CSV</span>
            </a>
            <button
              onClick={exportInventoryJson}
              className="inline-flex items-center space-x-1.5 bg-[#161d2b] hover:bg-[#1e273a] text-slate-200 border border-[#232d42] px-3.5 py-2 rounded-xl text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-indigo-400" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={handlePrint}
              className="inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-colors"
            >
              <Printer className="w-4 h-4" />
              <span>Print / Save PDF</span>
            </button>
          </div>
        </div>

        {/* Official Report Document */}
        <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-8 shadow-2xl print:border-none print:shadow-none print:bg-white print:text-black space-y-8">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-[#232d42] pb-6 gap-4">
            <div>
              <div className="text-[11px] font-mono text-blue-400 uppercase tracking-widest font-semibold mb-1">
                Official Digital Forensic Investigation Report
              </div>
              <h1 className="text-3xl font-extrabold font-mono tracking-tight text-white print:text-black">
                {report.scanId}
              </h1>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Generated: {new Date(report.timestamps.generated || report.timestamps.completed || report.timestamps.created).toUTCString()}
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
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 bg-[#0b0e14] p-5 rounded-xl border border-[#232d42] text-xs font-mono print:bg-slate-100 print:text-black">
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
              <span className="text-slate-500 uppercase block">Game Target</span>
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

            <div>
              <span className="text-slate-500 uppercase block">Consent Decided</span>
              <div className="text-slate-200 font-semibold flex items-center space-x-1 mt-0.5 print:text-black">
                <FileCheck2 className="w-3.5 h-3.5 text-amber-400" />
                <span>{report.timestamps.consent ? new Date(report.timestamps.consent).toLocaleTimeString() : 'Approved'}</span>
              </div>
            </div>
          </div>

          {/* Findings Summary Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center font-mono">
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
            <div className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42]">
              <div className="text-2xl font-bold text-slate-400">{report.summary.informational ?? 0}</div>
              <div className="text-[11px] text-slate-500 uppercase mt-1">Informational Records</div>
            </div>
          </div>

          {/* SECTION: FILE DISCOVERY & EXECUTABLE INVENTORY (MANDATORY REQUIREMENT 6 & 7) */}
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-[#232d42] pb-3 gap-2">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 font-mono flex items-center space-x-2">
                  <FileBox className="w-4 h-4 text-blue-400" />
                  <span>Comprehensive Executable &amp; JAR Inventory</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Complete catalog of all discovered executables, libraries, Java archives, and drivers across inspected drive volumes.
                </p>
              </div>

              {/* Totals Summary Badges */}
              <div className="flex items-center space-x-2 font-mono text-[11px]">
                <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400">
                  EXE: {invSummary.totalExe}
                </span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  JAR: {invSummary.totalJar}
                </span>
                <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                  DLL: {invSummary.totalDll}
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">
                  SYS: {invSummary.totalSys}
                </span>
              </div>
            </div>

            {/* Inventory Metric Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5 font-mono text-center text-xs">
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-blue-400">{invSummary.totalExe}</div>
                <div className="text-[10px] text-slate-500 uppercase">EXE Discovered</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-emerald-400">{invSummary.totalJar}</div>
                <div className="text-[10px] text-slate-500 uppercase">JAR Discovered</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-indigo-400">{invSummary.totalDll}</div>
                <div className="text-[10px] text-slate-500 uppercase">DLL Discovered</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-amber-400">{invSummary.totalSys}</div>
                <div className="text-[10px] text-slate-500 uppercase">SYS Drivers</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-slate-200">{invSummary.totalHashed}</div>
                <div className="text-[10px] text-slate-500 uppercase">Hashed SHA-256</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-teal-400">{invSummary.totalSigned}</div>
                <div className="text-[10px] text-slate-500 uppercase">Valid Signatures</div>
              </div>
              <div className="p-3 rounded-xl bg-[#0b0e14] border border-[#232d42]">
                <div className="text-lg font-bold text-slate-400">{invSummary.totalUnsigned}</div>
                <div className="text-[10px] text-slate-500 uppercase">Unsigned Binaries</div>
              </div>
            </div>

            {/* Inventory Tabs */}
            <div className="flex items-center space-x-1 border-b border-[#232d42] pt-2 overflow-x-auto print:hidden font-mono text-xs">
              {(
                [
                  { id: 'ALL' as const, label: 'All Files', count: invSummary.totalFiles },
                  { id: 'EXE' as const, label: 'EXE Files', count: invSummary.totalExe },
                  { id: 'JAR' as const, label: 'JAR Files', count: invSummary.totalJar },
                  { id: 'DLL' as const, label: 'DLL Files', count: invSummary.totalDll },
                  { id: 'SYS' as const, label: 'SYS Files', count: invSummary.totalSys },
                  { id: 'OTHER' as const, label: 'Other Formats', count: undefined },
                  { id: 'HISTORICAL' as const, label: 'Historical File Records', count: undefined },
                ]
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => {
                    setActiveTab(tab.id);
                    setInvPage(1);
                  }}
                  className={`px-3.5 py-2 font-medium border-b-2 transition-colors whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label} {tab.count !== undefined && <span className="text-[11px] opacity-70">({tab.count})</span>}
                </button>
              ))}
            </div>

            {/* Filters Bar */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs print:hidden">
              <div className="relative w-full sm:w-80">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search filename, path, publisher, hash..."
                  value={invSearch}
                  onChange={(e) => {
                    setInvSearch(e.target.value);
                    setInvPage(1);
                  }}
                  className="w-full pl-9 pr-3 py-2 bg-[#0b0e14] border border-[#232d42] rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex items-center space-x-2 w-full sm:w-auto">
                <select
                  value={invGameFilter}
                  onChange={(e) => {
                    setInvGameFilter(e.target.value);
                    setInvPage(1);
                  }}
                  className="px-3 py-2 bg-[#0b0e14] border border-[#232d42] rounded-xl text-slate-300 focus:outline-none focus:border-blue-500"
                >
                  <option value="">All Games</option>
                  <option value="minecraft">Minecraft</option>
                  <option value="fivem">FiveM</option>
                  <option value="roblox">Roblox</option>
                  <option value="r6siege">Rainbow Six</option>
                </select>

                <select
                  value={invStatusFilter}
                  onChange={(e) => {
                    setInvStatusFilter(e.target.value);
                    setInvPage(1);
                  }}
                  className="px-3 py-2 bg-[#0b0e14] border border-[#232d42] rounded-xl text-slate-300 focus:outline-none focus:border-blue-500"
                >
                  <option value="">All Detection States</option>
                  <option value="Clean">Clean</option>
                  <option value="CheatUtility">Cheat Utility Client</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="UnderReview">Inaccessible / Locked</option>
                </select>
              </div>
            </div>

            {/* Inventory Table */}
            <div className="border border-[#232d42] rounded-xl overflow-hidden bg-[#0b0e14]">
              {invLoading ? (
                <div className="p-12 text-center">
                  <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                  <span className="text-xs font-mono text-slate-400">Loading file inventory records...</span>
                </div>
              ) : !inventory || inventory.items.length === 0 ? (
                <div className="p-8 text-center text-xs font-mono text-slate-500">
                  No files matching the active filter criteria. Discovered files across all drives will appear here.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-[#121722] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#232d42]">
                      <tr>
                        <th className="py-2.5 px-3">Filename</th>
                        <th className="py-2.5 px-2">Type</th>
                        <th className="py-2.5 px-3">Discovered Path</th>
                        <th className="py-2.5 px-2 text-right">Size</th>
                        <th className="py-2.5 px-2">Signature / Publisher</th>
                        <th className="py-2.5 px-2">Game</th>
                        <th className="py-2.5 px-2">Classification</th>
                        <th className="py-2.5 px-2">Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f2738]/60 text-slate-300">
                      {inventory.items.map((file, idx) => (
                        <tr
                          key={idx}
                          onClick={() => setSelectedFileDetail(file)}
                          className="hover:bg-[#161d2b]/60 cursor-pointer transition-colors"
                        >
                          <td className="py-2 px-3 font-semibold text-white whitespace-nowrap">
                            {file.fileName}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              file.extension === '.jar' ? 'bg-emerald-500/20 text-emerald-400' :
                              file.extension === '.exe' ? 'bg-blue-500/20 text-blue-400' :
                              file.extension === '.sys' ? 'bg-amber-500/20 text-amber-400' :
                              'bg-indigo-500/20 text-indigo-400'
                            }`}>
                              {file.actualFileType || file.extension.toUpperCase().replace('.', '')}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-slate-400 max-w-xs truncate" title={file.fullPath}>
                            {file.fullPath}
                          </td>
                          <td className="py-2 px-2 text-right text-slate-400 whitespace-nowrap">
                            {formatFileSize(file.fileSizeBytes)}
                          </td>
                          <td className="py-2 px-2 text-slate-400 max-w-[140px] truncate" title={file.publisher || file.digitalSignatureState}>
                            {file.digitalSignatureState.includes('Signed') ? (
                              <span className="text-teal-400 flex items-center space-x-1">
                                <ShieldCheck className="w-3 h-3 shrink-0" />
                                <span className="truncate">{file.publisher || 'Signed'}</span>
                              </span>
                            ) : (
                              <span className="text-slate-500">Unsigned</span>
                            )}
                          </td>
                          <td className="py-2 px-2 uppercase text-[10px] text-slate-400 whitespace-nowrap">
                            {file.associatedGame || '—'}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {file.detectionStatus === 'CheatUtility' ? (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                                Cheat Utility
                              </span>
                            ) : file.detectionStatus === 'Suspicious' ? (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                                Suspicious
                              </span>
                            ) : file.fileAnalysisStatus === 'Inaccessible' ? (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-300">
                                Inaccessible
                              </span>
                            ) : (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400">
                                Clean
                              </span>
                            )}
                          </td>
                          <td className="py-2 px-2 text-slate-400 text-[10px] whitespace-nowrap">
                            {file.discoverySource}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Pagination controls */}
              {inventory && inventory.totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-2.5 bg-[#121722] border-t border-[#232d42] font-mono text-xs print:hidden">
                  <span className="text-slate-400">
                    Showing {(invPage - 1) * 25 + 1} - {Math.min(invPage * 25, inventory.totalItems)} of {inventory.totalItems} files
                  </span>
                  <div className="flex items-center space-x-2">
                    <button
                      disabled={invPage <= 1}
                      onClick={() => setInvPage((p) => Math.max(1, p - 1))}
                      className="px-2.5 py-1 rounded bg-[#0b0e14] border border-[#232d42] text-slate-300 disabled:opacity-40 hover:bg-[#1a2333]"
                    >
                      <ChevronLeft className="w-3.5 h-3.5" />
                    </button>
                    <span className="text-slate-300 text-xs">
                      Page {invPage} of {inventory.totalPages}
                    </span>
                    <button
                      disabled={invPage >= inventory.totalPages}
                      onClick={() => setInvPage((p) => Math.min(inventory.totalPages, p + 1))}
                      className="px-2.5 py-1 rounded bg-[#0b0e14] border border-[#232d42] text-slate-300 disabled:opacity-40 hover:bg-[#1a2333]"
                    >
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Section: Forensic Scan Coverage Matrix */}
          <div>
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
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono mb-4 border-b border-[#232d42] pb-2">
              Forensic Security Findings ({report.findings.length})
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
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                          f.severity === 'Warning' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                        }`}>
                          {f.severity}
                        </span>
                        <span className="text-slate-400">[{f.moduleId}]</span>
                        <span className="text-slate-300 font-bold">{f.findingId}</span>
                      </div>
                      <span className="text-blue-400 font-mono">{f.confidence}% Confidence</span>
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

        {/* File Detail Modal / Panel */}
        {selectedFileDetail && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-[#121722] border border-[#232d42] rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between border-b border-[#232d42] pb-3">
                <div className="flex items-center space-x-2">
                  <span className="text-blue-400 font-mono text-xs font-bold">{selectedFileDetail.fileId}</span>
                  <h3 className="text-sm font-bold text-white">{selectedFileDetail.fileName}</h3>
                </div>
                <button
                  onClick={() => setSelectedFileDetail(null)}
                  className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded"
                >
                  ✕ Close
                </button>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">Full Path</span>
                  <span className="text-slate-200 break-all">{selectedFileDetail.fullPath}</span>
                </div>

                <div className="grid grid-cols-2 gap-3 bg-[#0b0e14] p-3 rounded-xl border border-[#232d42]">
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Actual File Type</span>
                    <span className="text-blue-400 font-semibold">{selectedFileDetail.actualFileType}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">File Size</span>
                    <span className="text-slate-200">{formatFileSize(selectedFileDetail.fileSizeBytes)}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Digital Signature</span>
                    <span className={selectedFileDetail.digitalSignatureState.includes('Signed') ? 'text-teal-400' : 'text-slate-400'}>
                      {selectedFileDetail.digitalSignatureState}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Publisher / Signer</span>
                    <span className="text-slate-200 truncate block">{selectedFileDetail.publisher || 'N/A'}</span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block uppercase text-[10px]">SHA-256 Hash</span>
                  <span className="text-slate-300 break-all bg-[#0b0e14] p-2 rounded block border border-[#232d42] text-[11px]">
                    {selectedFileDetail.sha256Hash}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Discovery Context</span>
                    <span className="text-indigo-400">{selectedFileDetail.discoveryContext}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Detection Classification</span>
                    <span className={
                      selectedFileDetail.detectionStatus === 'CheatUtility' ? 'text-rose-400 font-bold' :
                      selectedFileDetail.detectionStatus === 'Suspicious' ? 'text-amber-400 font-bold' : 'text-emerald-400'
                    }>
                      {selectedFileDetail.detectionStatus}
                    </span>
                  </div>
                </div>

                {selectedFileDetail.detectionNotes && (
                  <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-300 text-[11px]">
                    <strong>Analysis Note:</strong> {selectedFileDetail.detectionNotes}
                  </div>
                )}
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setSelectedFileDetail(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-semibold"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
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
