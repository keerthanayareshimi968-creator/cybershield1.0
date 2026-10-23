import React from 'react';
import { NavTab } from './Sidebar';
import { Shield, PlusCircle, Upload, Play, Flame, Bell } from 'lucide-react';

interface TopbarProps {
  currentTab: NavTab;
  onNavigate: (tab: NavTab) => void;
  onOpenRegisterModal?: () => void;
  onOpenUploadModal?: () => void;
  anomalyCount?: number;
}

export const Topbar: React.FC<TopbarProps> = ({
  currentTab,
  onNavigate,
  onOpenRegisterModal,
  onOpenUploadModal,
  anomalyCount = 0,
}) => {
  const titles: Record<NavTab, { title: string; subtitle: string }> = {
    dashboard: { title: 'Security Overview', subtitle: 'Real-time telemetry, fleet health, and update security metrics' },
    devices: { title: 'Virtual IoT Devices', subtitle: 'Monitor, configure, and inspect software-emulated IoT nodes' },
    firmware: { title: 'Firmware Lab', subtitle: 'Upload, inspect, and verify cryptographic container integrity' },
    emulation: { title: 'Emulation Lab', subtitle: 'State machine lifecycle control and Secure Boot simulation' },
    attack_sim: { title: 'Attack Simulation Lab', subtitle: 'Safe controlled attack scenarios and impact analysis' },
    verification: { title: 'Security Verification Pipeline', subtitle: 'Multi-stage validation engine and Ed25519 signature checks' },
    logs: { title: 'Security Event Logs', subtitle: 'Immutable audit trail of all verification decisions and alerts' },
    performance: { title: 'Performance Testing & Benchmarking', subtitle: 'Real cryptographic throughput and execution timers' },
    settings: { title: 'Platform Settings & Keystore', subtitle: 'Trusted Ed25519 public keys, security policies, and reset' },
  };

  const current = titles[currentTab] || { title: 'IoT CyberShield', subtitle: 'Secure OTA Platform' };

  return (
    <header className="h-16 border-b border-slate-800 bg-[#0F172A]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-10 shrink-0">
      {/* Title & Crumb */}
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono text-slate-500 uppercase">IoT CyberShield /</span>
        <h2 className="text-sm font-bold text-slate-200 tracking-wide">{current.title}</h2>
      </div>

      {/* Quick Action Buttons & Status */}
      <div className="flex items-center gap-3">
        {/* Quick action buttons */}
        <button
          onClick={() => onNavigate('devices')}
          className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
        >
          <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>Device Registry</span>
        </button>

        <button
          onClick={() => onNavigate('firmware')}
          className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
        >
          <Upload className="w-3.5 h-3.5 text-teal-400" />
          <span>Upload Firmware</span>
        </button>

        <button
          onClick={() => onNavigate('attack_sim')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gradient-to-r from-orange-500/20 to-red-500/20 hover:from-orange-500/30 hover:to-red-500/30 text-orange-300 border border-orange-500/40 transition-colors font-semibold"
        >
          <Flame className="w-3.5 h-3.5 text-orange-400" />
          <span>Attack Lab ↗</span>
        </button>

        {/* Environment Badge */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>EMULATION ACTIVE</span>
        </div>

        {/* Anomaly Alerts counter if any */}
        {anomalyCount > 0 && (
          <button
            onClick={() => onNavigate('logs')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-red-950/80 border border-red-500/60 text-red-300 text-xs font-mono font-bold animate-pulse"
            title={`${anomalyCount} active anomaly alerts`}
          >
            <Bell className="w-3.5 h-3.5 text-red-400" />
            <span>{anomalyCount} ALERTS</span>
          </button>
        )}
      </div>
    </header>
  );
};
