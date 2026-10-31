'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/context/AuthContext';
import { Shield, Search, Terminal, Lock, ArrowRight } from 'lucide-react';

export default function Home() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.push('/dashboard');
    }
  }, [isAuthenticated, isLoading, router]);

  return (
    <div className="min-h-screen bg-[#0b0e14] text-slate-100 flex flex-col justify-between selection:bg-blue-500 selection:text-white">
      {/* Top Header */}
      <header className="border-b border-[#232d42]/60 px-6 py-4 flex items-center justify-between max-w-7xl mx-auto w-full">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="text-xl font-bold tracking-tight">SyScan</span>
        </div>
        <div className="flex items-center space-x-3">
          <Link
            href="/login"
            className="text-sm font-medium text-slate-300 hover:text-white px-3.5 py-1.5 rounded-lg hover:bg-slate-800/50 transition-colors"
          >
            Sign In
          </Link>
          <Link
            href="/register"
            className="text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors shadow-lg shadow-blue-600/20"
          >
            Get Started
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-5xl mx-auto px-6 py-20 text-center flex-1 flex flex-col items-center justify-center">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono font-medium mb-8">
          <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          <span>ADVANCED DIGITAL FORENSICS PLATFORM</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl leading-tight">
          Comprehensive PC Forensics &amp; Game Cheat Detection
        </h1>

        <p className="mt-6 text-lg sm:text-xl text-slate-400 max-w-2xl leading-relaxed">
          SyScan reconstructs executable timelines, investigates deleted cheat remnants, analyzes game logs, and monitors kernel drivers through transparent, participant-consented forensic scans.
        </p>

        <div className="mt-10 flex flex-col sm:flex-row items-center gap-4">
          <Link
            href="/login"
            className="w-full sm:w-auto flex items-center justify-center space-x-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold px-8 py-3.5 rounded-xl shadow-xl shadow-blue-500/25 transition-all text-base"
          >
            <span>Launch Dashboard</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/register"
            className="w-full sm:w-auto flex items-center justify-center space-x-2 bg-[#161d2b] hover:bg-[#1e273a] text-slate-200 border border-[#232d42] font-semibold px-8 py-3.5 rounded-xl transition-all text-base"
          >
            <span>Create Investigator Account</span>
          </Link>
        </div>

        {/* Feature Cards Grid */}
        <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-6 text-left w-full">
          <div className="p-6 rounded-2xl bg-[#121722] border border-[#232d42] hover:border-blue-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400 mb-4">
              <Search className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Historical Remnants</h3>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed">
              Recovers Prefetch, UserAssist, and Recycle Bin execution records to detect cheats run prior to the investigation.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#121722] border border-[#232d42] hover:border-blue-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4">
              <Terminal className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">12 Forensic Modules</h3>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed">
              Modular collection covering processes, vulnerable kernel drivers, game installations, runtime logs, and anti-forensic indicators.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-[#121722] border border-[#232d42] hover:border-blue-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-4">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Single-Use Invitations</h3>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed">
              Cryptographically random, one-time invitation credentials with explicit participant consent prior to data collection.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#232d42]/60 py-6 text-center text-xs font-mono text-slate-400">
        SyScan Security Forensic System v1.0.0 • Zero Stealth Collection Policy
      </footer>
    </div>
  );
}
