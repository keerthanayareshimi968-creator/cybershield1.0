import React, { useState } from 'react';
import { VirtualDevice } from '../types';
import { api } from '../services/api';
import { Hologram3D } from '../visualization/Hologram3D';
import {
  Flame,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  ArrowRight,
  RefreshCw,
  Info,
} from 'lucide-react';

interface AttackSimulatorViewProps {
  devices: VirtualDevice[];
  onRefresh: () => Promise<void>;
}

export const AttackSimulatorView: React.FC<AttackSimulatorViewProps> = ({
  devices,
  onRefresh,
}) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [selectedScenario, setSelectedScenario] = useState<string>('invalid_signature');
  const [simResult, setSimResult] = useState<any | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedDevice = devices.find(d => d.id === selectedDeviceId) || devices[0];

  const scenarios = [
    {
      id: 'invalid_signature',
      name: 'Forged / Corrupted Digital Signature',
      badge: 'CRYPTO INTEGRITY',
      desc: 'Adversary modifies bytes or provides an untrusted signature without possessing the development Ed25519 private key.',
      check: 'Ed25519 Digital Signature Authenticity',
    },
    {
      id: 'modified_firmware',
      name: 'Firmware Payload Modification (Tampering)',
      badge: 'HASH MISMATCH',
      desc: 'Adversary injects malicious bytes into firmware.bin post-signing, resulting in SHA-256 mismatch against manifest.',
      check: 'Firmware Binary Hash Verification',
    },
    {
      id: 'downgrade',
      name: 'Rollback / Firmware Downgrade Attack',
      badge: 'VERSION REVERSAL',
      desc: 'Adversary submits an older firmware version to force the device to reintroduce known unpatched CVE vulnerabilities.',
      check: 'Monotonic Version & Rollback Protection',
    },
    {
      id: 'replay',
      name: 'Update Token Replay Attack',
      badge: 'ANTI-REPLAY',
      desc: 'Adversary sniffs and retransmits an authentic past update identifier over the network to disrupt state.',
      check: 'Anti-Replay Token Validation',
    },
    {
      id: 'unknown_key',
      name: 'Untrusted / Rogue Signing Key',
      badge: 'KEYSTORE REJECTION',
      desc: 'Signed by an unauthorized third-party key identifier not registered in the hardware root keystore.',
      check: 'Ed25519 Digital Signature Authenticity',
    },
    {
      id: 'malformed',
      name: 'Malformed Package Container / Zip Slip',
      badge: 'PARSER GUARD',
      desc: 'Corrupted container or missing mandatory metadata attempting directory traversal or parser crash.',
      check: 'Firmware Package Archive',
    },
  ];

  const handleRunSimulation = async () => {
    if (!selectedDeviceId) return;
    setIsRunning(true);
    setErrorMsg(null);

    try {
      const res = await api.runSimulation(selectedDeviceId, selectedScenario);
      setSimResult(res);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Attack Simulation Lab</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Execute safe, controlled attack scenarios to visualize defensive responses and component impact.
        </p>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-200">✕</button>
        </div>
      )}

      {/* Target Node Selection & Trigger */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-orange-500/20 border border-orange-500/30 flex items-center justify-center shrink-0">
            <Flame className="w-5 h-5 text-orange-400" />
          </div>
          <div>
            <label className="text-[10px] font-mono font-bold text-slate-400 uppercase">Target Virtual Node</label>
            <select
              value={selectedDeviceId}
              onChange={e => {
                setSelectedDeviceId(e.target.value);
                setSimResult(null);
              }}
              className="block bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 mt-0.5"
            >
              {devices.map(d => (
                <option key={d.id} value={d.id}>
                  {d.id} — {d.name} ({d.type}, Current: v{d.firmware_version})
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleRunSimulation}
          disabled={isRunning}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white shadow-lg shadow-orange-500/20 transition-all shrink-0"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{isRunning ? 'Running Scenario…' : 'Execute Attack Scenario'}</span>
        </button>
      </div>

      {/* Scenario Grid Selector */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {scenarios.map(sc => {
          const isSelected = selectedScenario === sc.id;
          return (
            <div
              key={sc.id}
              onClick={() => {
                setSelectedScenario(sc.id);
                setSimResult(null);
              }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-gradient-to-b from-orange-950/40 to-slate-900 border-orange-500/80 shadow-lg shadow-orange-500/10'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-800 text-orange-400 border border-slate-700">
                  {sc.badge}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  Target: {sc.check}
                </span>
              </div>
              <h3 className="text-xs font-bold text-slate-200 mb-1">{sc.name}</h3>
              <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{sc.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Attack Impact Visualization Panel (Section 13) */}
      {simResult && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <span className="text-[10px] font-mono font-bold text-orange-400 uppercase tracking-widest">
                ATTACK IMPACT VISUALIZATION & DEFENSE MONITOR
              </span>
              <h2 className="text-base font-bold text-slate-100 mt-0.5">
                Scenario Outcome: {simResult.title}
              </h2>
            </div>
            <span className="text-xs font-mono font-bold px-3 py-1 rounded-md bg-red-950 text-red-300 border border-red-700">
              {simResult.status}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* 3D Hologram Highlighting Affected Component */}
            <div className="lg:col-span-6">
              <h4 className="text-xs font-mono font-bold text-slate-300 mb-2 uppercase flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                <span>Hologram Twin · Component Defense State</span>
              </h4>
              <Hologram3D
                deviceType={simResult.deviceType}
                deviceStatus="UPDATE_REJECTED"
                securityStatus="WARNING"
                affectedComponent={simResult.affectedComponent}
                highlightError={true}
                deviceName={simResult.deviceName}
              />
              <p className="text-[10px] font-mono text-slate-500 mt-2 text-center">
                Pulsing red highlights the simulated affected subsystem protected by OTA policy.
              </p>
            </div>

            {/* Impact Details & Defensive Actions */}
            <div className="lg:col-span-6 space-y-3.5 text-xs">
              <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">Target Node:</span>
                  <span className="font-mono font-bold text-slate-200">
                    {simResult.deviceName} ({simResult.deviceId})
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">Failed Policy Check:</span>
                  <span className="font-mono font-bold text-red-400">{simResult.failedCheck}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">Potentially Affected Component:</span>
                  <span className="font-mono font-semibold text-orange-300">
                    {simResult.affectedComponent}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">Firmware State:</span>
                  <span className="font-mono font-bold text-teal-300">
                    Retained Trusted v{simResult.currentFirmwareVersion}
                  </span>
                </div>
              </div>

              <div className="p-4 bg-red-950/20 rounded-xl border border-red-500/30 space-y-1">
                <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-wider block">
                  Potential Real-World Consequence
                </span>
                <p className="text-slate-200 leading-relaxed font-sans">{simResult.potentialImpact}</p>
                <span className="text-[10px] text-slate-500 italic block mt-1">
                  Potential impact — illustrative simulation.
                </span>
              </div>

              <div className="p-4 bg-emerald-950/20 rounded-xl border border-emerald-500/30 space-y-1">
                <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider block">
                  Defensive Action Enforced
                </span>
                <p className="text-emerald-200 leading-relaxed font-sans">{simResult.defensiveAction}</p>
              </div>

              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>{simResult.notice}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
