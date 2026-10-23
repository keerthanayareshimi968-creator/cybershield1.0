import React, { useState } from 'react';
import { VirtualDevice, SecurityEvent, SimulationSession } from '../types';
import { Hologram3D } from '../visualization/Hologram3D';
import { NavTab } from '../components/Sidebar';
import {
  Cpu,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Flame,
  ArrowRight,
  Upload,
  Terminal,
  Activity,
  Server,
  PlusCircle,
} from 'lucide-react';

interface DashboardViewProps {
  metrics: {
    totalDevices: number;
    onlineDevices: number;
    attentionDevices: number;
    firmwareTests: number;
    approvedUpdates: number;
    rejectedUpdates: number;
    totalSimulations: number;
    unacknowledgedAnomalies: number;
  };
  devices: VirtualDevice[];
  recentEvents: SecurityEvent[];
  recentSimulations: SimulationSession[];
  onNavigate: (tab: NavTab) => void;
  onSelectDeviceForInspection?: (deviceId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  devices,
  recentEvents,
  recentSimulations,
  onNavigate,
}) => {
  const [selectedDeviceIndex, setSelectedDeviceIndex] = useState(0);
  const activeDevice = devices[selectedDeviceIndex] || devices[0];

  return (
    <div className="space-y-6">
      {/* Page Heading & Quick Action CTA */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-2xl border border-slate-800">
        <div>
          <span className="text-[10px] font-mono tracking-widest text-cyan-400 font-bold uppercase">
            TELEMETRY REGISTRY · SOFTWARE EMULATION ACTIVE
          </span>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight mt-0.5">
            IoT Security Operations Center
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Monitor software-emulated IoT nodes, inspect cryptographic firmware integrity, and run controlled OTA attack simulations.
          </p>
        </div>

        {/* 4 Working CTA Buttons specified in Section 4 */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onNavigate('devices')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-all"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Register Device</span>
          </button>
          <button
            onClick={() => onNavigate('firmware')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 transition-all"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Firmware</span>
          </button>
          <button
            onClick={() => onNavigate('emulation')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 transition-all"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Start Emulation</span>
          </button>
          <button
            onClick={() => onNavigate('attack_sim')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white shadow-lg shadow-orange-500/20 transition-all"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Attack Simulator ↗</span>
          </button>
        </div>
      </div>

      {/* Metrics Row (Derived from Database) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">VIRTUAL NODES</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-slate-100">
            {String(metrics.totalDevices).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Configured endpoints</p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">ONLINE NODES</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-400">
            {String(metrics.onlineDevices).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Simulators running</p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">ATTENTION</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-orange-400">
            {String(metrics.attentionDevices).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Degraded / Warning</p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">TESTS RUN</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-slate-100">
            {String(metrics.firmwareTests).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">OTA evaluations</p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">APPROVED</span>
            <CheckCircle2 className="w-4 h-4 text-teal-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-teal-400">
            {String(metrics.approvedUpdates).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Checks passed</p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider">BLOCKED</span>
            <XCircle className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-red-400">
            {String(metrics.rejectedUpdates).padStart(2, '0')}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Attacks stopped</p>
        </div>
      </div>

      {/* Middle Grid: Device Fleet + Hologram 3D Visualization */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Device Fleet Table (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100">Virtual Device Fleet</h3>
                <p className="text-xs text-slate-400">Select a device below to inspect its holographic twin.</p>
              </div>
              <button
                onClick={() => onNavigate('devices')}
                className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>View All</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[10px] font-mono uppercase tracking-wider">
                    <th className="pb-3 px-2">DEVICE NODE</th>
                    <th className="pb-3 px-2">FIRMWARE</th>
                    <th className="pb-3 px-2">MINIMUM</th>
                    <th className="pb-3 px-2">STATE</th>
                    <th className="pb-3 px-2">SECURITY</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {devices.map((device, idx) => {
                    const isSelected = selectedDeviceIndex === idx;
                    const isRunning = device.device_status === 'RUNNING' || device.device_status === 'HEALTHY';
                    return (
                      <tr
                        key={device.id}
                        onClick={() => setSelectedDeviceIndex(idx)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-cyan-500/10 text-cyan-200' : 'hover:bg-slate-800/40 text-slate-300'
                        }`}
                      >
                        <td className="py-3 px-2 font-sans font-medium flex items-center gap-2">
                          <div
                            className={`w-2 h-2 rounded-full ${
                              device.security_status === 'COMPROMISED'
                                ? 'bg-red-500'
                                : isRunning
                                ? 'bg-emerald-400'
                                : 'bg-slate-500'
                            }`}
                          />
                          <div>
                            <p className="font-semibold text-slate-200">{device.name}</p>
                            <span className="text-[10px] font-mono text-slate-500">{device.id}</span>
                          </div>
                        </td>
                        <td className="py-3 px-2">v{device.firmware_version}</td>
                        <td className="py-3 px-2 text-slate-400">v{device.minimum_version}</td>
                        <td className="py-3 px-2">
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                              isRunning
                                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                                : device.device_status === 'DEGRADED'
                                ? 'bg-orange-950/80 text-orange-300 border border-orange-800/60'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {device.device_status}
                          </span>
                        </td>
                        <td className="py-3 px-2">
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                              device.security_status === 'SECURE'
                                ? 'text-teal-300 bg-teal-950/80 border border-teal-800/60'
                                : 'text-red-300 bg-red-950/80 border border-red-800/60'
                            }`}
                          >
                            {device.security_status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>
              Showing {devices.length} configured software nodes · Persistent SQLite Storage
            </span>
            <button
              onClick={() => onNavigate('emulation')}
              className="text-cyan-400 hover:text-cyan-300 font-semibold text-xs"
            >
              Control state machine →
            </button>
          </div>
        </div>

        {/* Interactive Holographic Twin (5 cols) */}
        <div className="lg:col-span-5 flex flex-col">
          {activeDevice && (
            <Hologram3D
              deviceType={activeDevice.type}
              deviceStatus={activeDevice.device_status}
              securityStatus={activeDevice.security_status}
              deviceName={activeDevice.name}
            />
          )}
        </div>
      </div>

      {/* Bottom Grid: Recent Security Events & Simulation Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Events Feed */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100">Live Security Audit Feed</h3>
            </div>
            <button
              onClick={() => onNavigate('logs')}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recentEvents.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                No security events recorded yet. Run a verification or simulation.
              </div>
            ) : (
              recentEvents.map(evt => {
                const isHigh = evt.severity === 'HIGH' || evt.severity === 'CRITICAL';
                return (
                  <div
                    key={evt.id}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="flex items-start gap-2.5">
                      <div
                        className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                          isHigh ? 'bg-red-400' : 'bg-cyan-400'
                        }`}
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-slate-300">
                            {evt.device_id || 'SYSTEM'}
                          </span>
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold ${
                              isHigh
                                ? 'bg-red-950 text-red-400 border border-red-800/60'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {evt.event_type}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] mt-1 line-clamp-1">{evt.description}</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {new Date(evt.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Recent Controlled Simulations */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              <h3 className="text-sm font-bold text-slate-100">Recent Controlled Attack Simulations</h3>
            </div>
            <button
              onClick={() => onNavigate('attack_sim')}
              className="text-xs font-semibold text-orange-400 hover:text-orange-300 flex items-center gap-1"
            >
              <span>Run Scenario</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recentSimulations.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                No attack simulations run yet. Click "Run Scenario" to test defenses.
              </div>
            ) : (
              recentSimulations.map(sim => (
                <div
                  key={sim.id}
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-200">{sim.title}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded font-bold bg-red-950 text-red-400 border border-red-800/60">
                        {sim.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                      <span className="text-orange-400 font-mono font-medium">Defense:</span> {sim.defense_action}
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                    {sim.device_id}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
