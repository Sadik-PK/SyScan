'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { Shield, PlusCircle, History, LayoutDashboard, LogOut, Activity } from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  const navItems = [
    { label: 'Overview', href: '/dashboard', icon: LayoutDashboard },
    { label: 'Scan History', href: '/dashboard/scans', icon: History },
    { label: 'New Scan', href: '/dashboard/scans/new', icon: PlusCircle },
  ];

  return (
    <header className="border-b border-[#232d42] bg-[#0e121a]/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <Link href="/dashboard" className="flex items-center space-x-2.5 group">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-white">SyScan</span>
              <span className="text-[10px] ml-1 px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono font-medium border border-blue-500/20">
                PRO
              </span>
            </div>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center space-x-1 ml-8">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2234]'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right side user info & actions */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Activity className="w-3 h-3 animate-pulse" />
            <span>OPERATIONAL</span>
          </div>

          {user && (
            <div className="flex items-center space-x-3 pl-2 border-l border-[#232d42]">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-slate-200">{user.displayName}</div>
                <div className="text-[11px] text-slate-400 font-mono truncate max-w-[140px]">{user.email}</div>
              </div>
              <button
                onClick={handleLogout}
                title="Log out"
                className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

