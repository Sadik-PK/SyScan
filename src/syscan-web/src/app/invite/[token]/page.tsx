'use client';

import React, { useEffect, useState, Suspense } from 'react';
import { useParams } from 'next/navigation';
import { validateInvitation, InvitationValidation } from '@/lib/api';
import {
  Shield,
  Download,
  Copy,
  Check,
  Lock,
  Gamepad2,
  Building2,
  User,
  AlertCircle,
  ExternalLink,
  Layers,
  Sparkles,
  ArrowDownToLine
} from 'lucide-react';

function ParticipantInviteContent() {
  const params = useParams();
  const token = params.token as string;

  const [info, setInfo] = useState<InvitationValidation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [downloadStarted, setDownloadStarted] = useState(false);

  useEffect(() => {
    const checkToken = async () => {
      try {
        setLoading(true);
        const data = await validateInvitation(token);
        setInfo(data);
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Invitation is invalid or has expired.');
        }
      } finally {
        setLoading(false);
      }
    };

    if (token) checkToken();
  }, [token]);

  const copyToken = () => {
    navigator.clipboard.writeText(token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleDownloadApp = () => {
    // 1. Copy token to clipboard automatically
    copyToken();
    setDownloadStarted(true);

    // 2. Trigger browser download of SyScan.exe
    const link = document.createElement('a');
    link.href = '/downloads/SyScan.exe';
    link.download = 'SyScan.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    // 3. Reset download state after 5 seconds
    setTimeout(() => setDownloadStarted(false), 5000);
  };

  const openInApp = () => {
    // Triggers custom URI protocol registered by SyScan Desktop
    window.location.href = `syscan://invite/${token}`;
  };

  return (
    <div className="min-h-screen bg-[#0b0e14] text-slate-100 flex flex-col justify-between selection:bg-blue-500 selection:text-white">
      {/* Header */}
      <header className="border-b border-[#232d42]/60 px-6 py-4 flex items-center justify-between max-w-4xl mx-auto w-full">
        <div className="flex items-center space-x-2.5">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="text-lg font-bold tracking-tight">SyScan</span>
        </div>
        <span className="text-xs font-mono text-slate-400">PARTICIPANT INVITATION</span>
      </header>

      {/* Main Container */}
      <main className="max-w-xl mx-auto px-4 py-12 w-full flex-1 flex flex-col justify-center">
        {loading ? (
          <div className="text-center p-12">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-xs font-mono text-slate-400">Verifying secure scan invitation...</p>
          </div>
        ) : error || !info ? (
          <div className="bg-[#121722] border border-rose-500/30 rounded-2xl p-8 text-center shadow-2xl">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 text-rose-400 flex items-center justify-center mx-auto mb-4">
              <AlertCircle className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-white">Invalid or Expired Invitation</h2>
            <p className="text-xs text-slate-400 mt-2 max-w-sm mx-auto leading-relaxed">
              {error || 'This scan invitation link has expired, was cancelled, or has already been used by another device.'}
            </p>
            <p className="text-xs text-slate-500 mt-4 font-mono">
              Please contact your tournament administrator or referee to issue a fresh invitation.
            </p>
          </div>
        ) : (
          <div className="bg-[#121722] border border-[#232d42] rounded-2xl p-7 shadow-2xl space-y-6">
            {/* Invitation Header */}
            <div>
              <div className="inline-block px-2.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono text-[11px] font-semibold mb-2">
                OFFICIAL SCAN INVITATION
              </div>
              <h2 className="text-xl font-bold text-white">PC Forensic Scan Requested</h2>
              <p className="text-xs text-slate-400 mt-1">
                You have been invited to participate in a verification scan.
              </p>
            </div>

            {/* Scope Details Card */}
            <div className="bg-[#0b0e14] rounded-xl border border-[#232d42] p-4 space-y-3 text-xs font-mono">
              <div className="flex items-center justify-between py-1 border-b border-[#232d42]/60">
                <span className="text-slate-500 flex items-center space-x-1.5">
                  <Building2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>ORGANIZATION</span>
                </span>
                <span className="text-slate-200 font-bold">{info.organizationName}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#232d42]/60">
                <span className="text-slate-500 flex items-center space-x-1.5">
                  <User className="w-3.5 h-3.5 text-indigo-400" />
                  <span>PARTICIPANT</span>
                </span>
                <span className="text-slate-200 font-bold">{info.participantLabel}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#232d42]/60">
                <span className="text-slate-500 flex items-center space-x-1.5">
                  <Gamepad2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>GAME TARGET</span>
                </span>
                <span className="text-slate-200 uppercase font-bold">{info.gameId}</span>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-slate-500 flex items-center space-x-1.5">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>SCAN ID</span>
                </span>
                <span className="text-blue-400 font-bold">{info.scanId}</span>
              </div>
            </div>

            {/* Primary Action: Download SyScan Desktop Linked With This Invite */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  Get Started With SyScan
                </h3>
                <span className="text-[11px] font-mono text-emerald-400 flex items-center space-x-1">
                  <Sparkles className="w-3 h-3" />
                  <span>Portable • No Installation</span>
                </span>
              </div>

              {/* Big Download Button */}
              <button
                onClick={handleDownloadApp}
                className="w-full flex items-center justify-center space-x-2.5 bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-400 text-white font-bold py-3.5 px-4 rounded-xl shadow-xl shadow-blue-600/30 transition-all text-sm group active:scale-[0.99]"
              >
                <ArrowDownToLine className="w-5 h-5 group-hover:translate-y-0.5 transition-transform" />
                <span>
                  {downloadStarted ? 'Downloading SyScan.exe (Token Copied!)' : 'Download SyScan Desktop (.exe)'}
                </span>
              </button>

              {downloadStarted && (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center space-x-2 animate-fadeIn">
                  <Check className="w-4 h-4 shrink-0" />
                  <span>Your download has started! The pairing token was automatically copied to your clipboard.</span>
                </div>
              )}

              {/* Secondary Actions: Open If Already Installed or Copy Token */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                <button
                  onClick={openInApp}
                  className="flex items-center justify-center space-x-1.5 bg-[#0b0e14] hover:bg-[#161d2b] text-slate-300 border border-[#232d42] font-semibold py-2.5 rounded-xl transition-all text-xs"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-blue-400" />
                  <span>Open in Desktop App</span>
                </button>

                <button
                  onClick={copyToken}
                  className="flex items-center justify-center space-x-1.5 bg-[#0b0e14] hover:bg-[#161d2b] text-slate-300 border border-[#232d42] font-semibold py-2.5 rounded-xl transition-all text-xs"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied Token!' : 'Copy Token'}</span>
                </button>
              </div>
            </div>

            {/* Quick 3-Step Guide */}
            <div className="p-4 rounded-xl bg-[#0b0e14] border border-[#232d42] space-y-2.5 text-xs text-slate-400">
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-bold">
                Quick Instructions
              </div>
              <div className="space-y-2">
                <div className="flex items-start space-x-2.5">
                  <div className="w-4 h-4 rounded-full bg-blue-500/20 text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[10px] mt-0.5">
                    1
                  </div>
                  <p>Click <strong className="text-slate-200">Download SyScan Desktop</strong> above to save the scanner executable.</p>
                </div>

                <div className="flex items-start space-x-2.5">
                  <div className="w-4 h-4 rounded-full bg-blue-500/20 text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[10px] mt-0.5">
                    2
                  </div>
                  <p>Run <strong className="text-slate-200">SyScan.exe</strong> on your PC. It will automatically connect with this invitation.</p>
                </div>

                <div className="flex items-start space-x-2.5">
                  <div className="w-4 h-4 rounded-full bg-blue-500/20 text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[10px] mt-0.5">
                    3
                  </div>
                  <p>Review the requested scan scope and click <strong className="text-slate-200">Approve &amp; Start Scan</strong>.</p>
                </div>
              </div>
            </div>

            {/* Privacy Guarantee Note */}
            <div className="p-3.5 rounded-xl bg-blue-500/5 border border-blue-500/20 flex items-start space-x-2.5 text-xs text-blue-300">
              <Lock className="w-4 h-4 shrink-0 text-blue-400 mt-0.5" />
              <div className="text-[11px] leading-relaxed">
                <strong>Zero Concealed Collection:</strong> SyScan does not execute covert background scans. All modules must be explicitly reviewed and accepted by you before data is read.
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#232d42]/60 py-6 text-center text-xs font-mono text-slate-500">
        SyScan Digital Forensics • Windows 10/11 x64 Architecture
      </footer>
    </div>
  );
}

export default function ParticipantInvitePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#0b0e14] flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <ParticipantInviteContent />
    </Suspense>
  );
}
