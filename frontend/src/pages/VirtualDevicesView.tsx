import React, { useState } from 'react';
import { VirtualDevice, DeviceType } from '../types';
import { api } from '../services/api';
import { Hologram3D } from '../visualization/Hologram3D';
import {
  Plus,
  Play,
  Square,
  Trash2,
  Edit2,
  Cpu,
  Activity,
  Layers,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  HardDrive,
  Wifi,
  Settings as SettingsIcon,
  X,
} from 'lucide-react';

interface VirtualDevicesViewProps {
  devices: VirtualDevice[];
  onRefresh: () => Promise<void>;
  onSelectForUpdate?: (deviceId: string) => void;
}

export const VirtualDevicesView: React.FC<VirtualDevicesViewProps> = ({
  devices,
  onRefresh,
}) => {
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedDevice, setSelectedDevice] = useState<VirtualDevice | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // New Device Form state
  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<DeviceType>('camera');
  const [newVersion, setNewVersion] = useState('2.0.0');
  const [newMinVersion, setNewMinVersion] = useState('1.8.0');

  const filteredDevices = devices.filter(d => {
    if (categoryFilter === 'all') return true;
    return d.type === categoryFilter;
  });

  const handleStartDevice = async (id: string) => {
    setLoadingAction(`start-${id}`);
    setErrorMsg(null);
    try {
      const res = await api.startDevice(id);
      if (!res.success) {
        setErrorMsg(res.reason || 'Secure Boot verification rejected device startup.');
      }
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleStopDevice = async (id: string) => {
    setLoadingAction(`stop-${id}`);
    try {
      await api.stopDevice(id);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleDeleteDevice = async (id: string) => {
    setLoadingAction(`delete-${id}`);
    try {
      await api.deleteDevice(id);
      setDeleteConfirmId(null);
      if (selectedDevice?.id === id) setSelectedDevice(null);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleCreateDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setLoadingAction('create');
    try {
      await api.createDevice({
        id: newId,
        name: newName,
        type: newType,
        firmwareVersion: newVersion,
        minimumVersion: newMinVersion,
      });
      setIsAddModalOpen(false);
      setNewId('');
      setNewName('');
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setLoadingAction(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Virtual IoT Devices</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Software-emulated endpoints running virtual firmware stacks and secure boot monitors.
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all shadow-lg shadow-cyan-500/20"
        >
          <Plus className="w-4 h-4" />
          <span>Add Virtual Node</span>
        </button>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Submenu / Category Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'all', label: 'All Devices' },
          { id: 'camera', label: 'Cameras (Tapo C200)' },
          { id: 'environmental_sensor', label: 'Environmental (DHT22)' },
          { id: 'smart_lock', label: 'Smart Lock (ESP32 DevKit)' },
          { id: 'router', label: 'Network Router (Archer C6)' },
        ].map(cat => (
          <button
            key={cat.id}
            onClick={() => setCategoryFilter(cat.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              categoryFilter === cat.id
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Devices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filteredDevices.map(device => {
          const isRunning = device.device_status === 'RUNNING' || device.device_status === 'HEALTHY';
          const isSelected = selectedDevice?.id === device.id;
          const tel = device.telemetry;

          return (
            <div
              key={device.id}
              className={`bg-slate-900/80 border rounded-2xl p-5 flex flex-col justify-between transition-all ${
                isSelected
                  ? 'border-cyan-500 shadow-lg shadow-cyan-500/10'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              {/* Card Header */}
              <div>
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div>
                    <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                      {device.type.replace('_', ' ')}
                    </span>
                    <h3 className="text-base font-bold text-slate-100">{device.name}</h3>
                    <p className="text-[11px] font-mono text-slate-500">{device.id}</p>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      isRunning
                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                        : device.device_status === 'DEGRADED'
                        ? 'bg-orange-950/80 text-orange-300 border border-orange-800/60'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {device.device_status}
                  </span>
                </div>

                {/* Firmware Policy Specs */}
                <div className="grid grid-cols-2 gap-2 my-4 p-3 bg-slate-950/60 rounded-xl border border-slate-800/60 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Active Version</span>
                    <span className="text-cyan-300 font-bold">v{device.firmware_version}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Hardware Minimum</span>
                    <span className="text-slate-300">v{device.minimum_version}</span>
                  </div>
                </div>

                {/* Live Telemetry Gauges if running */}
                {isRunning && tel && (
                  <div className="grid grid-cols-3 gap-2 my-3 text-[11px] font-mono text-center">
                    <div className="p-2 bg-slate-950/40 rounded-lg border border-slate-800/40">
                      <span className="text-[9px] text-slate-500 block">CPU LOAD</span>
                      <span className="font-bold text-cyan-400">{tel.cpuPercent}%</span>
                    </div>
                    <div className="p-2 bg-slate-950/40 rounded-lg border border-slate-800/40">
                      <span className="text-[9px] text-slate-500 block">RAM</span>
                      <span className="font-bold text-teal-400">{tel.memoryPercent}%</span>
                    </div>
                    <div className="p-2 bg-slate-950/40 rounded-lg border border-slate-800/40">
                      <span className="text-[9px] text-slate-500 block">NET</span>
                      <span className="font-bold text-slate-200">{tel.networkKbps} KB/s</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Card Footer Actions */}
              <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  {isRunning ? (
                    <button
                      onClick={() => handleStopDevice(device.id)}
                      disabled={loadingAction === `stop-${device.id}`}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 transition-colors"
                      title="Stop simulated device"
                    >
                      <Square className="w-3 h-3" />
                      <span>Halt</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleStartDevice(device.id)}
                      disabled={loadingAction === `start-${device.id}`}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/50 transition-colors"
                      title="Simulate Secure Boot startup"
                    >
                      <Play className="w-3 h-3" />
                      <span>Secure Boot</span>
                    </button>
                  )}

                  <button
                    onClick={() => setSelectedDevice(device)}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    3D Twin
                  </button>
                </div>

                <button
                  onClick={() => setDeleteConfirmId(device.id)}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-800 transition-colors"
                  title="Remove device"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Device 3D Twin & Inspector Drawer */}
      {selectedDevice && (
        <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-bold text-slate-100">
                Inspection Twin: {selectedDevice.name} ({selectedDevice.id})
              </h2>
            </div>
            <button
              onClick={() => setSelectedDevice(null)}
              className="text-slate-400 hover:text-slate-200 p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-6">
              <Hologram3D
                deviceType={selectedDevice.type}
                deviceStatus={selectedDevice.device_status}
                securityStatus={selectedDevice.security_status}
                deviceName={selectedDevice.name}
              />
            </div>
            <div className="lg:col-span-6 space-y-3 text-xs">
              <div className="p-4 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2">
                <h4 className="font-mono font-bold text-cyan-300 uppercase text-[11px]">Hardware & Security Baseline</h4>
                <div className="grid grid-cols-2 gap-2 text-slate-300">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Trusted Signer Key:</span>
                    <span className="font-mono">{selectedDevice.trusted_key_id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Boot ROM Hash:</span>
                    <span className="font-mono truncate block" title={selectedDevice.boot_hash || ''}>
                      {selectedDevice.boot_hash ? `${selectedDevice.boot_hash.substring(0, 16)}...` : 'Not set'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Last Update Time:</span>
                    <span>{selectedDevice.last_update_time ? new Date(selectedDevice.last_update_time).toLocaleString() : 'Factory Image'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Security Status:</span>
                    <span className="font-bold text-teal-400">{selectedDevice.security_status}</span>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-slate-950/70 rounded-xl border border-slate-800">
                <h4 className="font-mono font-bold text-slate-300 uppercase text-[11px] mb-2">Device Configuration (JSON)</h4>
                <pre className="p-3 bg-slate-900 rounded font-mono text-[11px] text-cyan-200 overflow-x-auto">
                  {JSON.stringify(selectedDevice.config || {}, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-sm w-full space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-base font-bold text-slate-100">Confirm Deletion</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Are you sure you want to remove virtual node <strong className="text-slate-200 font-mono">{deleteConfirmId}</strong>? All associated telemetry and accepted replay tokens will be purged.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteDevice(deleteConfirmId)}
                className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white transition-colors"
              >
                Delete Device
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Device Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-slate-100">Register Virtual Device</h3>
              <button onClick={() => setIsAddModalOpen(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateDevice} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Unique Device ID</label>
                <input
                  required
                  value={newId}
                  onChange={e => setNewId(e.target.value.toUpperCase())}
                  placeholder="e.g. DEV-CAM-09"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">Must be unique across the fleet.</span>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Device Friendly Name</label>
                <input
                  required
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="e.g. Loading Dock Security Camera"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Hardware / Device Category</label>
                <select
                  value={newType}
                  onChange={e => setNewType(e.target.value as DeviceType)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="camera">Smart Camera (TP-Link Tapo C200)</option>
                  <option value="smart_lock">Smart Access Locker (ESP32 DevKit)</option>
                  <option value="environmental_sensor">Environmental Sensor (DHT22 / AM2302)</option>
                  <option value="router">Network Router (TP-Link Archer C6)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Initial Firmware Version</label>
                  <input
                    required
                    value={newVersion}
                    onChange={e => setNewVersion(e.target.value)}
                    placeholder="2.0.0"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Hardware Minimum Version</label>
                  <input
                    required
                    value={newMinVersion}
                    onChange={e => setNewMinVersion(e.target.value)}
                    placeholder="1.8.0"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loadingAction === 'create'}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  {loadingAction === 'create' ? 'Registering…' : 'Register Node'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
