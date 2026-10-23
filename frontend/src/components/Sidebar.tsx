import React from 'react';
import {
  LayoutDashboard,
  Cpu,
  FileCode,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  ListOrdered,
  Gauge,
  Settings,
  Shield,
  CircleDot,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'devices'
  | 'firmware'
  | 'emulation'
  | 'attack_sim'
  | 'verification'
  | 'logs'
  | 'performance'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onlineCount?: number;
  alertCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  onlineCount = 4,
  alertCount = 0,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'devices', label: 'Virtual Devices', icon: Cpu, badge: onlineCount ? `${onlineCount} ON` : undefined },
    { id: 'firmware', label: 'Firmware Lab', icon: FileCode },
    { id: 'emulation', label: 'Emulation Lab', icon: Terminal },
    { id: 'attack_sim', label: 'Attack Simulator', icon: ShieldAlert, badge: '6 LABS' },
    { id: 'verification', label: 'Security Verification', icon: ShieldCheck },
    { id: 'logs', label: 'Security Logs', icon: ListOrdered },
    { id: 'performance', label: 'Performance Testing', icon: Gauge },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0F172A] border-r border-slate-800 flex flex-col justify-between h-screen shrink-0 sticky top-0 z-20">
      {/* Brand Header */}
      <div>
        <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-teal-500 p-0.5 shadow-lg shadow-cyan-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <h1 className="font-extrabold text-base tracking-tight bg-gradient-to-r from-cyan-200 via-teal-300 to-white bg-clip-text text-transparent">
              IoT CyberShield
            </h1>
            <p className="text-[10px] font-mono font-medium text-slate-400 uppercase tracking-widest">
              SECURE OTA PLATFORM
            </p>
          </div>
        </div>

        {/* Navigation list */}
        <div className="px-3 py-4">
          <p className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
            SECURITY CONTROL
          </p>
          <nav className="space-y-1">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id as NavTab)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-teal-500/10 text-cyan-300 border-l-4 border-cyan-400 shadow-sm font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold ${
                        item.id === 'attack_sim'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40">
        <div className="flex items-center gap-2 mb-1.5 text-xs font-mono text-cyan-400">
          <CircleDot className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span className="font-semibold">Software Emulation Active</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Prototype test sandbox. Harmless test binaries only; no physical IoT hardware connected.
        </p>
      </div>
    </aside>
  );
};
