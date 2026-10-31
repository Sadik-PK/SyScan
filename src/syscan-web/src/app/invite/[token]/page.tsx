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
  Layers
} from 'lucide-react';

function ParticipantInviteContent() {
  const params = useParams();
  const token = params.token as string;

  const [info, setInfo] = useState<InvitationValidation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

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
    setTimeout(() => setCopied(false), 2000);
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

            {/* Instructions Steps */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                How to Complete This Scan
              </h3>

              <div className="space-y-2 text-xs text-slate-400">
                <div className="flex items-start space-x-2.5">
                  <div className="w-5 h-5 rounded-full bg-[#1c2436] text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[11px]">
                    1
                  </div>
                  <p>
                    Ensure <strong>SyScan Desktop</strong> is installed on your Windows PC.
                  </p>
                </div>

                <div className="flex items-start space-x-2.5">
                  <div className="w-5 h-5 rounded-full bg-[#1c2436] text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[11px]">
                    2
                  </div>
                  <p>
                    Click <strong>Open in SyScan Desktop</strong> below or paste the token into the app.
                  </p>
                </div>

                <div className="flex items-start space-x-2.5">
                  <div className="w-5 h-5 rounded-full bg-[#1c2436] text-blue-400 font-mono font-bold flex items-center justify-center shrink-0 text-[11px]">
                    3
                  </div>
                  <p>
                    Review the requested modules and click <strong>Approve &amp; Start Scan</strong> to begin.
                  </p>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="space-y-2 pt-2">
              <button
                onClick={openInApp}
                className="w-full flex items-center justify-center space-x-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold py-3 rounded-xl shadow-xl shadow-blue-500/25 transition-all text-sm"
              >
                <span>Open in SyScan Desktop</span>
                <ExternalLink className="w-4 h-4" />
              </button>

              <button
                onClick={copyToken}
                className="w-full flex items-center justify-center space-x-2 bg-[#0b0e14] hover:bg-[#161d2b] text-slate-300 border border-[#232d42] font-semibold py-2.5 rounded-xl transition-all text-xs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied Invitation Token' : 'Copy Invitation Token'}</span>
              </button>
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
