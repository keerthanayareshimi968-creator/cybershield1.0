import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  Settings as SettingsIcon,
  KeyRound,
  ShieldAlert,
  Database,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Save,
} from 'lucide-react';

interface SettingsViewProps {
  onRefreshAll?: () => Promise<void>;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onRefreshAll }) => {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [trustedKeys, setTrustedKeys] = useState<any[]>([]);
  const [isResetConfirmOpen, setIsResetConfirmOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchSettings = async () => {
    try {
      const data = await api.getSettings();
      setSettings(data.settings);
      setTrustedKeys(data.trustedKeys);
    } catch (err: any) {
      setErrorMsg(err.message);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      await api.updateSettings(settings);
      setSuccessMsg('Settings updated successfully in SQLite database.');
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetDemo = async () => {
    setIsLoading(true);
    try {
      await api.resetDemoData();
      setIsResetConfirmOpen(false);
      setSuccessMsg('All demo sessions, update history, and anomaly alerts reset.');
      if (onRefreshAll) await onRefreshAll();
      await fetchSettings();
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Platform Settings & Keystore</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Manage hardware root keys, upload limits, rollback security overrides, and database storage.
        </p>
      </div>

      {successMsg && (
        <div className="p-3 bg-teal-950/80 border border-teal-500/60 rounded-xl text-xs text-teal-200 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-teal-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200">
          {errorMsg}
        </div>
      )}

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <SettingsIcon className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100">Security & Storage Policies</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Maximum Firmware Upload Size (MB)</label>
              <input
                type="number"
                min="1"
                max="50"
                value={settings.max_upload_size_mb || '10'}
                onChange={e => setSettings({ ...settings, max_upload_size_mb: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Default limit: 10 MB per archive.</span>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Rule-Based Anomaly Detection</label>
              <select
                value={settings.anomaly_detection_active || 'true'}
                onChange={e => setSettings({ ...settings, anomaly_detection_active: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="true">Active (Flag repeated rejections & suspicious spikes)</option>
                <option value="false">Disabled (Quiet mode)</option>
              </select>
            </div>
          </div>

          {/* Emergency Downgrade Override Section */}
          <div className="p-4 rounded-xl bg-orange-950/20 border border-orange-500/40 space-y-2 mt-4">
            <div className="flex items-center gap-2 text-orange-400">
              <AlertTriangle className="w-4 h-4" />
              <h4 className="text-xs font-bold uppercase tracking-wider">
                Authorized Factory Recovery / Downgrade Override (Dev Demo Only)
              </h4>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              In production, monotonic rollback protection strictly rejects version regressions. This option allows demonstration of an authorized administrator factory restore.
            </p>
            <div className="flex items-center gap-3 pt-1">
              <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-orange-200">
                <input
                  type="checkbox"
                  checked={settings.allow_emergency_downgrade === 'true'}
                  onChange={e => setSettings({ ...settings, allow_emergency_downgrade: e.target.checked ? 'true' : 'false' })}
                  className="rounded border-slate-700 text-orange-500 focus:ring-0"
                />
                <span>Allow emergency firmware version downgrade</span>
              </label>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isLoading ? 'Saving…' : 'Save Policies'}</span>
            </button>
          </div>
        </div>
      </form>

      {/* Trusted Signing Keys Keystore */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100">Hardware Root Keystore (Ed25519 Public Keys)</h3>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            PRIVATE KEYS NEVER EXPOSED
          </span>
        </div>

        <div className="space-y-3">
          {trustedKeys.map(k => (
            <div
              key={k.key_id}
              className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-cyan-300">{k.key_id}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded font-bold bg-teal-950 text-teal-300 border border-teal-800/60">
                    {k.algorithm}
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded font-bold bg-slate-800 text-slate-300">
                    {k.is_active ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                </div>
                <p className="text-slate-300 text-xs mt-1">{k.name}</p>
                <p className="text-[10px] font-mono text-slate-500 mt-1 break-all">
                  Public Key (Hex): {k.public_key_hex}
                </p>
              </div>

              <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                Registered: {new Date(k.created_at).toLocaleDateString()}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Reset Demo Section */}
      <div className="bg-slate-900/80 border border-red-500/30 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-red-300">Reset Prototype Sandbox Data</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Clear test attack sessions, update histories, and alert records back to baseline.
          </p>
        </div>

        <button
          onClick={() => setIsResetConfirmOpen(true)}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-red-950 hover:bg-red-900 text-red-300 border border-red-800/60 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Demo Data</span>
        </button>
      </div>

      {/* Reset Confirmation Modal */}
      {isResetConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-sm w-full space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-base font-bold text-slate-100">Confirm Reset</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              This will clear all simulation histories, accepted replay tokens, and temporary updates. Devices will be reset to their default state.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setIsResetConfirmOpen(false)}
                className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleResetDemo}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white"
              >
                Confirm Reset
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
