'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import Navbar from '@/components/Navbar';
import { createScan, CreateScanResponse } from '@/lib/api';
import {
  Shield,
  Copy,
  Check,
  ArrowRight,
  AlertCircle,
  FileCheck2,
  Gamepad2,
  Settings2,
  Lock
} from 'lucide-react';

const AVAILABLE_MODULES = [
  { id: 'process-scanner', name: 'Running Process Scanner', desc: 'Inspects running processes, PIDs, executables & signature matches', default: true },
  { id: 'service-scanner', name: 'Windows Service Scanner', desc: 'Enumerates installed services and vulnerable exploit drivers', default: true },
  { id: 'driver-scanner', name: 'Kernel Driver Scanner', desc: 'Scans System32\\drivers for blacklisted vulnerable signed binaries', default: true },
  { id: 'game-directory', name: 'Game Directory Scanner', desc: 'Checks game folders for unauthorized client mods, DLLs, and hooks', default: true },
  { id: 'game-log-analyzer', name: 'Game Log Analyzer', desc: 'Parses latest.log and runtime logs for injection and loader signatures', default: true },
  { id: 'file-system-scanner', name: 'Full File System Scanner', desc: 'Scans Temp and Downloads directories for suspicious cheat executables', default: false },
  { id: 'forensic-artifacts', name: 'Windows Forensic Artifacts', desc: 'Analyzes UserAssist, Prefetch & execution remnants to prove past launches', default: true },
  { id: 'installed-apps', name: 'Installed Application Inventory', desc: 'Checks registry uninstall keys for cheat utilities and macro software', default: true },
  { id: 'registry-scanner', name: 'Windows Registry Scanner', desc: 'Inspects Run and RunOnce persistence keys for suspicious entries', default: true },
  { id: 'event-log-scanner', name: 'Windows Event Log Scanner', desc: 'Checks for anti-forensic log wipe events (1102 / 104) & driver install (7045)', default: true },
  { id: 'file-deletion', name: 'Deleted File Investigation', desc: 'Investigates Recycle Bin remnants for deleted cheat binaries', default: true },
  { id: 'anti-forensic', name: 'Anti-Forensic Investigation', desc: 'Detects Prefetch tampering, journal wipes, and audit manipulation', default: true },
];

export default function CreateScanPage() {
  const router = useRouter();

  const [participantLabel, setParticipantLabel] = useState('');
  const [gameId, setGameId] = useState('minecraft');
  const [scanProfileId, setScanProfileId] = useState('standard');
  const [expiryMinutes, setExpiryMinutes] = useState(60);
  const [selectedModules, setSelectedModules] = useState<string[]>(
    AVAILABLE_MODULES.filter((m) => m.default).map((m) => m.id)
  );

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdResult, setCreatedResult] = useState<CreateScanResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const toggleModule = (id: string) => {
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const selectAll = () => setSelectedModules(AVAILABLE_MODULES.map((m) => m.id));
  const deselectAll = () => setSelectedModules([]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!participantLabel.trim()) {
      setError('Please provide participant or player label.');
      return;
    }
    if (selectedModules.length === 0) {
      setError('Please select at least one forensic scanning module.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await createScan({
        participantLabel: participantLabel.trim(),
        gameId,
        scanProfileId,
        enabledModules: selectedModules,
        invitationExpiryMinutes: expiryMinutes,
      });
      setCreatedResult(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to create scan invitation.');
      }
    } finally {
      setLoading(false);
    }
  };

  const getFullInvitationUrl = () => {
    if (!createdResult) return '';
    const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
    return `${origin}/invite/${createdResult.invitationToken}`;
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(getFullInvitationUrl());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-4xl w-full mx-auto px-4 sm:px-6 py-8">
        <div className="mb-8">
          <Link
            href="/dashboard"
            className="text-xs font-mono text-slate-500 hover:text-slate-300 transition-colors mb-2 inline-block"
          >
            ← Back to Overview
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-white">Create Forensic Scan Request</h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure permitted modules and generate a cryptographic one-time invitation link
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-start space-x-3 text-rose-400 text-xs">
            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Success Modal / Card when created */}
        {createdResult ? (
          <div className="bg-[#121722] border border-blue-500/40 rounded-2xl p-8 shadow-2xl">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mb-5">
              <FileCheck2 className="w-6 h-6" />
            </div>

            <div className="inline-block px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono font-medium mb-2">
              SCAN CREATED SUCCESSFULLY
            </div>
            <h2 className="text-xl font-bold text-white">Scan ID: {createdResult.scanId}</h2>
            <p className="text-sm text-slate-400 mt-1">
              Share the unique invitation link below with{' '}
              <strong className="text-slate-200">{participantLabel}</strong>.
            </p>

            <div className="mt-6 bg-[#0b0e14] border border-[#232d42] rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
              <span className="font-mono text-xs text-blue-300 truncate w-full sm:w-auto">
                {getFullInvitationUrl()}
              </span>
              <button
                onClick={copyToClipboard}
                className="w-full sm:w-auto shrink-0 inline-flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied Link' : 'Copy Link'}</span>
              </button>
            </div>

            <div className="mt-6 p-4 rounded-xl bg-[#161d2b] border border-[#232d42] text-xs text-slate-400 space-y-1">
              <div className="flex items-center space-x-2 text-slate-300 font-semibold mb-1">
                <Lock className="w-3.5 h-3.5 text-blue-400" />
                <span>Security Assurance</span>
              </div>
              <p>• The invitation token is single-use and valid for {expiryMinutes} minutes.</p>
              <p>• The participant must explicitly approve the scan modules on SyScan Desktop before data collection begins.</p>
              <p>• The participant will connect automatically to this exact scan session upon launching the scanner.</p>
            </div>

            <div className="mt-8 flex items-center justify-end space-x-3">
              <button
                onClick={() => {
                  setCreatedResult(null);
                  setParticipantLabel('');
                }}
                className="text-xs text-slate-400 hover:text-white px-4 py-2"
              >
                Create Another Scan
              </button>
              <button
                onClick={() => router.push(`/dashboard/scans/${createdResult.scanId}`)}
                className="inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs px-5 py-2.5 rounded-xl shadow-lg shadow-blue-600/20 transition-all"
              >
                <span>Go to Live Monitor</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Participant info */}
            <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-6">
              <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200 mb-4">
                <Gamepad2 className="w-4 h-4 text-blue-400" />
                <span>Target Investigation Scope</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 font-mono">
                    Participant Identifier / In-Game Name *
                  </label>
                  <input
                    type="text"
                    required
                    value={participantLabel}
                    onChange={(e) => setParticipantLabel(e.target.value)}
                    placeholder="e.g. CompetitivePlayer_99 or Discord Tag"
                    className="w-full px-3.5 py-2.5 bg-[#0b0e14] border border-[#232d42] rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 font-mono">
                    Selected Game Platform *
                  </label>
                  <select
                    value={gameId}
                    onChange={(e) => setGameId(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-[#0b0e14] border border-[#232d42] rounded-xl text-sm text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="minecraft">Minecraft (Java Edition / Fabric / Forge)</option>
                    <option value="fivem">FiveM (Grand Theft Auto V)</option>
                    <option value="roblox">Roblox (Client &amp; Player)</option>
                    <option value="r6siege">Rainbow Six Siege</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 font-mono">
                    Scan Profile
                  </label>
                  <select
                    value={scanProfileId}
                    onChange={(e) => setScanProfileId(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-[#0b0e14] border border-[#232d42] rounded-xl text-sm text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="standard">Standard Tournament Investigation</option>
                    <option value="strict">Strict Comprehensive PC Forensic</option>
                    <option value="fast">Rapid Process &amp; Memory Check</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 font-mono">
                    Invitation Expiry
                  </label>
                  <select
                    value={expiryMinutes}
                    onChange={(e) => setExpiryMinutes(Number(e.target.value))}
                    className="w-full px-3.5 py-2.5 bg-[#0b0e14] border border-[#232d42] rounded-xl text-sm text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value={30}>30 Minutes</option>
                    <option value={60}>60 Minutes (Recommended)</option>
                    <option value={120}>2 Hours</option>
                    <option value={1440}>24 Hours</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Modules checklist */}
            <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200">
                  <Settings2 className="w-4 h-4 text-blue-400" />
                  <span>Authorized Collection Modules ({selectedModules.length}/{AVAILABLE_MODULES.length})</span>
                </div>
                <div className="flex items-center space-x-2 text-xs">
                  <button
                    type="button"
                    onClick={selectAll}
                    className="text-blue-400 hover:text-blue-300 font-mono"
                  >
                    Select All
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    type="button"
                    onClick={deselectAll}
                    className="text-slate-500 hover:text-slate-300 font-mono"
                  >
                    Clear
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {AVAILABLE_MODULES.map((mod) => {
                  const isChecked = selectedModules.includes(mod.id);
                  return (
                    <div
                      key={mod.id}
                      onClick={() => toggleModule(mod.id)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                        isChecked
                          ? 'bg-blue-600/10 border-blue-500/40 text-slate-100'
                          : 'bg-[#0b0e14] border-[#232d42] text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start space-x-3">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => {}}
                          className="mt-1 w-4 h-4 rounded text-blue-600 focus:ring-0 bg-[#0b0e14] border-[#232d42]"
                        />
                        <div className="flex-1">
                          <div className="text-xs font-semibold text-slate-200">{mod.name}</div>
                          <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{mod.desc}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end space-x-3 pt-2">
              <Link
                href="/dashboard"
                className="px-5 py-2.5 rounded-xl text-xs font-semibold text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </Link>
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs px-6 py-2.5 rounded-xl shadow-lg shadow-blue-600/20 transition-all disabled:opacity-50"
              >
                <Shield className="w-3.5 h-3.5" />
                <span>{loading ? 'Generating Invitation...' : 'Generate Scan Invitation'}</span>
              </button>
            </div>
          </form>
        )}
      </main>
    </div>
  );
}

