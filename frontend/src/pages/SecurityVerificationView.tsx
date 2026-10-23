import React, { useState } from 'react';
import { VirtualDevice, VerificationResult } from '../types';
import { api } from '../services/api';
import {
  ShieldCheck,
  Shield,
  Layers,
  Lock,
  Hash,
  RotateCcw,
  RefreshCw,
  Cpu,
  CheckCircle2,
  XCircle,
  AlertCircle,
  FileCode,
} from 'lucide-react';

interface SecurityVerificationViewProps {
  devices: VirtualDevice[];
}

export const SecurityVerificationView: React.FC<SecurityVerificationViewProps> = ({ devices }) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [activeStage, setActiveStage] = useState<number>(0);
  const [testResult, setTestResult] = useState<VerificationResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const stages = [
    {
      id: 'structure',
      num: '01',
      title: 'Container & Archive Structure',
      icon: Layers,
      summary: 'Inspects ZIP archive entries in memory for zip-slip path traversal and validates manifest.json, firmware.bin, firmware.sig presence.',
      algorithm: 'JSZip In-Memory Stream Validation',
      threatMitigated: 'Directory Traversal, Malformed ZIP Bomb, Corrupted Archive Parser Exploits',
    },
    {
      id: 'hash',
      num: '02',
      title: 'Cryptographic SHA-256 Integrity',
      icon: Hash,
      summary: 'Independently calculates SHA-256 over raw extracted firmware.bin binary bytes. Never trusts manifest hash alone.',
      algorithm: 'FIPS 180-4 SHA-256 Digest (256-bit)',
      threatMitigated: 'Man-in-the-Middle Binary Tampering, Bit-Rot, Mirror Injection',
    },
    {
      id: 'signature',
      num: '03',
      title: 'Ed25519 Digital Signature Authenticity',
      icon: Lock,
      summary: 'Verifies asymmetric digital signature over canonicalized manifest fields using the trusted public key registered in the hardware keystore.',
      algorithm: 'RFC 8032 PureEd25519 (Edwards-curve Digital Signature)',
      threatMitigated: 'Firmware Forgery, Rogue Signer, Impersonated Upstream Vendor',
    },
    {
      id: 'compatibility',
      num: '04',
      title: 'Hardware Device Compatibility',
      icon: Cpu,
      summary: 'Confirms package target device type strictly matches destination node hardware architecture.',
      algorithm: 'Hardware Target Specifier Matching',
      threatMitigated: 'Cross-Device Flashing, Incompatible Pinout Brick Disruption',
    },
    {
      id: 'rollback',
      num: '05',
      title: 'Monotonic Rollback Protection',
      icon: RotateCcw,
      summary: 'Compares proposed semantic version (major.minor.patch) against device active version and hardware minimum version limit.',
      algorithm: 'Monotonic Numeric Version Comparator',
      threatMitigated: 'Firmware Downgrade Attack to Revive Known Deprecated Vulnerabilities',
    },
    {
      id: 'replay',
      num: '06',
      title: 'Anti-Replay Token Registry',
      icon: ShieldCheck,
      summary: 'Guarantees that each update ID has never previously been accepted for this specific device node in persistent SQLite database.',
      algorithm: 'Single-Use UUID Ledger & DB Transaction Check',
      threatMitigated: 'Network Packet Replay, Flash Memory Cycle Exhaustion Attacks',
    },
  ];

  const handleRunLiveTest = async (valid: boolean) => {
    if (!selectedDeviceId) return;
    setIsLoading(true);

    try {
      const pkg = await api.generateSamplePackage(selectedDeviceId, valid ? 'valid' : 'invalid_signature');
      const res = await api.verifyFirmware(selectedDeviceId, pkg.fileId);
      setTestResult(res);
    } catch {
      // handled
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Security Verification Engine</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Detailed architecture of the 6-stage mandatory cryptographic verification pipeline.
        </p>
      </div>

      {/* 6 Pipeline Stage Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {stages.map((st, idx) => {
          const Icon = st.icon;
          const isSelected = activeStage === idx;
          return (
            <div
              key={st.id}
              onClick={() => setActiveStage(idx)}
              className={`p-5 rounded-2xl border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-gradient-to-b from-cyan-950/40 to-slate-900 border-cyan-400 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xl font-mono font-bold text-cyan-400">{st.num}</span>
                <div className={`p-2 rounded-lg ${isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>

              <h3 className="text-sm font-bold text-slate-100 mb-2">{st.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">{st.summary}</p>

              <div className="pt-3 border-t border-slate-800/80 space-y-1 text-[11px] font-mono">
                <div className="text-slate-400">
                  <span className="text-slate-500">Method:</span> {st.algorithm}
                </div>
                <div className="text-teal-400 font-medium">
                  <span className="text-slate-500">Defense:</span> {st.threatMitigated}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Pipeline Test Runner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Live Stage Execution Sandbox</h3>
            <p className="text-xs text-slate-400">
              Run real test evaluations through all 6 security stages simultaneously.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedDeviceId}
              onChange={e => setSelectedDeviceId(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200"
            >
              {devices.map(d => (
                <option key={d.id} value={d.id}>
                  {d.id} ({d.name})
                </option>
              ))}
            </select>

            <button
              onClick={() => handleRunLiveTest(true)}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-teal-500/20 hover:bg-teal-500/30 text-teal-300 border border-teal-500/40"
            >
              Test Valid Update
            </button>
            <button
              onClick={() => handleRunLiveTest(false)}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50"
            >
              Test Attack Update
            </button>
          </div>
        </div>

        {testResult && (
          <div className="space-y-3 pt-2">
            <div
              className={`p-3.5 rounded-xl border flex items-center justify-between ${
                testResult.decision === 'APPROVED'
                  ? 'bg-teal-950/60 border-teal-500/50 text-teal-300'
                  : 'bg-red-950/60 border-red-500/50 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2.5 text-xs font-semibold">
                {testResult.decision === 'APPROVED' ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                <span>Final Decision: {testResult.decision} — {testResult.reason}</span>
              </div>
              <span className="font-mono text-[10px] text-slate-400">
                Update ID: {testResult.updateId}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {testResult.checks.map(chk => (
                <div
                  key={chk.id}
                  className={`p-3 rounded-xl border text-xs ${
                    chk.status === 'PASSED'
                      ? 'bg-slate-950/60 border-slate-800 text-slate-300'
                      : 'bg-red-950/30 border-red-800/50 text-red-300'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-bold text-slate-200">{chk.name}</span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold ${
                        chk.status === 'PASSED' ? 'bg-teal-950 text-teal-300' : 'bg-red-950 text-red-300'
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{chk.detail}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
