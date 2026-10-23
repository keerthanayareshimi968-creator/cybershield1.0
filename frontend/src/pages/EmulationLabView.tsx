import React, { useState } from 'react';
import { VirtualDevice } from '../types';
import { api } from '../services/api';
import { Hologram3D } from '../visualization/Hologram3D';
import {
  Terminal,
  Play,
  Square,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  RefreshCw,
  Clock,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Cpu,
} from 'lucide-react';

interface EmulationLabViewProps {
  devices: VirtualDevice[];
  onRefresh: () => Promise<void>;
}

export const EmulationLabView: React.FC<EmulationLabViewProps> = ({
  devices,
  onRefresh,
}) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [bootResult, setBootResult] = useState<any | null>(null);
  const [attestationChallenge, setAttestationChallenge] = useState<any | null>(null);
  const [attestationReport, setAttestationReport] = useState<any | null>(null);
  const [attestationVerification, setAttestationVerification] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedDevice = devices.find(d => d.id === selectedDeviceId) || devices[0];

  const handleSecureBoot = async () => {
    if (!selectedDeviceId) return;
    setIsLoading(true);
    setErrorMsg(null);
    setBootResult(null);

    try {
      const res = await api.startDevice(selectedDeviceId);
      setBootResult(res);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStop = async () => {
    if (!selectedDeviceId) return;
    setIsLoading(true);
    setErrorMsg(null);
    try {
      await api.stopDevice(selectedDeviceId);
      setBootResult(null);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateChallenge = async () => {
    if (!selectedDeviceId) return;
    setIsLoading(true);
    setErrorMsg(null);
    setAttestationVerification(null);

    try {
      const chal = await api.createChallenge(selectedDeviceId);
      setAttestationChallenge(chal);

      // Immediately generate signed report for the challenge
      const rep = await api.simulateAttestationReport(selectedDeviceId, chal.id, false);
      setAttestationReport(rep);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyAttestation = async (tamper: boolean = false) => {
    if (!attestationChallenge || !selectedDeviceId) return;
    setIsLoading(true);
    setErrorMsg(null);

    try {
      let reportToVerify = attestationReport;
      if (tamper) {
        // generate tampered report
        reportToVerify = await api.simulateAttestationReport(selectedDeviceId, attestationChallenge.id, true);
        setAttestationReport(reportToVerify);
      }
      const outcome = await api.verifyAttestationReport(selectedDeviceId, attestationChallenge.id, reportToVerify);
      setAttestationVerification(outcome);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const states = [
    'STOPPED',
    'RUNNING',
    'VERIFYING',
    'UPDATING',
    'HEALTHY',
    'DEGRADED',
    'UPDATE_REJECTED',
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Virtual Device Emulation Lab</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Software-based state machine controller, Secure Boot verification, and Remote Attestation.
        </p>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-200">✕</button>
        </div>
      )}

      {/* Target Device Selector Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-cyan-400 shrink-0" />
          <div>
            <label className="text-[10px] font-mono font-bold text-slate-400 uppercase">Target Emulated Node</label>
            <select
              value={selectedDeviceId}
              onChange={e => {
                setSelectedDeviceId(e.target.value);
                setBootResult(null);
                setAttestationChallenge(null);
                setAttestationReport(null);
                setAttestationVerification(null);
              }}
              className="block bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500 mt-0.5"
            >
              {devices.map(d => (
                <option key={d.id} value={d.id}>
                  {d.id} — {d.name} (Current: v{d.firmware_version})
                </option>
              ))}
            </select>
          </div>
        </div>

        {selectedDevice && (
          <div className="flex items-center gap-2">
            {selectedDevice.device_status === 'STOPPED' ? (
              <button
                onClick={handleSecureBoot}
                disabled={isLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-all shadow-lg shadow-emerald-500/20"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Simulate Secure Boot</span>
              </button>
            ) : (
              <button
                onClick={handleStop}
                disabled={isLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-500 text-white transition-all"
              >
                <Square className="w-3.5 h-3.5" />
                <span>Halt Simulation</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* Interactive State Machine Diagram */}
      {selectedDevice && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              State Machine Status: {selectedDevice.id}
            </h3>
            <span className="text-[10px] font-mono text-slate-500">
              Active State: <strong className="text-cyan-400">{selectedDevice.device_status}</strong>
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 pt-2">
            {states.map(st => {
              const isActive = selectedDevice.device_status === st;
              return (
                <div
                  key={st}
                  className={`p-3 rounded-xl border text-center transition-all ${
                    isActive
                      ? st === 'UPDATE_REJECTED'
                        ? 'bg-red-950/80 border-red-500 text-red-300 shadow-lg shadow-red-500/20 font-bold scale-105'
                        : 'bg-cyan-500/20 border-cyan-400 text-cyan-200 shadow-lg shadow-cyan-500/20 font-bold scale-105'
                      : 'bg-slate-950/40 border-slate-800 text-slate-500'
                  }`}
                >
                  <div
                    className={`w-2 h-2 rounded-full mx-auto mb-1.5 ${
                      isActive ? 'bg-cyan-400 animate-ping' : 'bg-slate-700'
                    }`}
                  />
                  <span className="text-[10px] font-mono block leading-tight">{st}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Two Column Layout: Secure Boot Evaluation & Remote Attestation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Secure Boot Record (6 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100">Secure Boot Verification</h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              SOFTWARE ROOT OF TRUST
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Checks boot partition image hash against trusted hardware ROM manifest and ensures active firmware complies with monotonic hardware version limits.
          </p>

          {!bootResult ? (
            <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
              Click &quot;Simulate Secure Boot&quot; above to execute bootloader integrity verification.
            </div>
          ) : (
            <div className="space-y-3">
              <div
                className={`p-3 rounded-xl border flex items-center gap-2.5 text-xs font-semibold ${
                  bootResult.success
                    ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
                    : 'bg-red-950/60 border-red-500/50 text-red-300'
                }`}
              >
                {bootResult.success ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>{bootResult.reason}</span>
              </div>

              <div className="space-y-2">
                {bootResult.checks.map((chk: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                  >
                    <div>
                      <span className="font-mono font-bold text-slate-200">{chk.name}</span>
                      <p className="text-[11px] text-slate-400 mt-0.5">{chk.detail}</p>
                    </div>
                    <span
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded whitespace-nowrap ${
                        chk.status === 'PASSED'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                          : 'bg-red-950 text-red-300 border border-red-800/60'
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Remote Attestation Lab (6 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100">Remote Attestation Simulation</h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              CHALLENGE-RESPONSE NONCE
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Issues an unpredictable single-use 32-byte cryptographic challenge nonce to bind the remote device measurement report.
          </p>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCreateChallenge}
              disabled={isLoading}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition-colors"
            >
              Issue Challenge Nonce
            </button>
            {attestationChallenge && (
              <>
                <button
                  onClick={() => handleVerifyAttestation(false)}
                  disabled={isLoading}
                  className="px-3 py-2 rounded-lg text-xs font-semibold bg-teal-500/20 hover:bg-teal-500/30 text-teal-300 border border-teal-500/40 transition-colors"
                >
                  Verify Authentic Report
                </button>
                <button
                  onClick={() => handleVerifyAttestation(true)}
                  disabled={isLoading}
                  className="px-3 py-2 rounded-lg text-xs font-semibold bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 transition-colors"
                  title="Tamper with report before sending"
                >
                  Simulate Tampered Report
                </button>
              </>
            )}
          </div>

          {attestationChallenge && (
            <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-xs font-mono space-y-1.5">
              <div className="flex justify-between text-slate-400">
                <span>Challenge ID:</span>
                <span className="text-slate-200">{attestationChallenge.id}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Fresh Nonce (Hex):</span>
                <span className="text-cyan-300 truncate max-w-[200px]" title={attestationChallenge.nonceHex}>
                  {attestationChallenge.nonceHex.substring(0, 24)}...
                </span>
              </div>
            </div>
          )}

          {attestationVerification && (
            <div className="space-y-2 pt-2">
              <div
                className={`p-3 rounded-xl border flex items-center gap-2.5 text-xs font-semibold ${
                  attestationVerification.status === 'VERIFIED'
                    ? 'bg-teal-950/60 border-teal-500/50 text-teal-300'
                    : 'bg-red-950/60 border-red-500/50 text-red-300'
                }`}
              >
                {attestationVerification.status === 'VERIFIED' ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                <span>{attestationVerification.reason}</span>
              </div>

              <div className="space-y-1.5">
                {attestationVerification.checks.map((chk: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-start justify-between text-xs"
                  >
                    <div>
                      <span className="font-mono font-bold text-slate-200">{chk.name}</span>
                      <p className="text-[11px] text-slate-400 mt-0.5">{chk.detail}</p>
                    </div>
                    <span
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded whitespace-nowrap ${
                        chk.status === 'PASSED'
                          ? 'bg-teal-950 text-teal-300 border border-teal-800/60'
                          : 'bg-red-950 text-red-300 border border-red-800/60'
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
