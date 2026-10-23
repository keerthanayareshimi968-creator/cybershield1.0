import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { DashboardView } from './pages/DashboardView';
import { VirtualDevicesView } from './pages/VirtualDevicesView';
import { FirmwareLabView } from './pages/FirmwareLabView';
import { EmulationLabView } from './pages/EmulationLabView';
import { AttackSimulatorView } from './pages/AttackSimulatorView';
import { SecurityVerificationView } from './pages/SecurityVerificationView';
import { SecurityLogsView } from './pages/SecurityLogsView';
import { PerformanceTestingView } from './pages/PerformanceTestingView';
import { SettingsView } from './pages/SettingsView';
import { api } from './services/api';
import { VirtualDevice, SecurityEvent, SimulationSession } from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [devices, setDevices] = useState<VirtualDevice[]>([]);
  const [metrics, setMetrics] = useState({
    totalDevices: 0,
    onlineDevices: 0,
    attentionDevices: 0,
    firmwareTests: 0,
    approvedUpdates: 0,
    rejectedUpdates: 0,
    totalSimulations: 0,
    unacknowledgedAnomalies: 0,
  });
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [recentSimulations, setRecentSimulations] = useState<SimulationSession[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    try {
      const data = await api.getDashboard();
      setMetrics(data.metrics);
      setRecentEvents(data.recentEvents);
      setRecentSimulations(data.recentSimulations);

      const deviceList = await api.getDevices();
      setDevices(deviceList);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // Poll telemetry and device state every 4 seconds
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex min-h-screen bg-[#0B0F19] text-slate-100 font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onlineCount={metrics.onlineDevices}
        alertCount={metrics.unacknowledgedAnomalies}
      />

      {/* Main Workspace Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar
          currentTab={currentTab}
          onNavigate={setCurrentTab}
          anomalyCount={metrics.unacknowledgedAnomalies}
        />

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {currentTab === 'dashboard' && (
            <DashboardView
              metrics={metrics}
              devices={devices}
              recentEvents={recentEvents}
              recentSimulations={recentSimulations}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'devices' && (
            <VirtualDevicesView
              devices={devices}
              onRefresh={loadData}
              onSelectForUpdate={() => setCurrentTab('firmware')}
            />
          )}

          {currentTab === 'firmware' && (
            <FirmwareLabView
              devices={devices}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'emulation' && (
            <EmulationLabView
              devices={devices}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'attack_sim' && (
            <AttackSimulatorView
              devices={devices}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'verification' && (
            <SecurityVerificationView
              devices={devices}
            />
          )}

          {currentTab === 'logs' && (
            <SecurityLogsView
              devices={devices}
            />
          )}

          {currentTab === 'performance' && (
            <PerformanceTestingView />
          )}

          {currentTab === 'settings' && (
            <SettingsView
              onRefreshAll={loadData}
            />
          )}
        </main>

        {/* Global Footer */}
        <footer className="border-t border-slate-800/80 p-4 px-6 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 bg-[#0F172A]/40">
          <span>
            IoT CyberShield Platform v2.0 · Software Emulation & Secure OTA Update Verification
          </span>
          <span className="font-mono text-[11px] text-slate-400">
            Node.js 22 · Ed25519 · Three.js · SQLite
          </span>
        </footer>
      </div>
    </div>
  );
};
