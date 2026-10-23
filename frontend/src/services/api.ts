import {
  VirtualDevice,
  VerificationResult,
  SecurityEvent,
  SimulationSession,
  AnomalyAlert,
  PerformanceBenchmark,
} from '../types';

const API_BASE = '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Server request failed');
  }
  return data;
}

export const api = {
  // Dashboard
  async getDashboard() {
    const res = await fetch(`${API_BASE}/dashboard`);
    return handleResponse<{
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
    }>(res);
  },

  // Devices
  async getDevices(): Promise<VirtualDevice[]> {
    const res = await fetch(`${API_BASE}/devices`);
    return handleResponse<VirtualDevice[]>(res);
  },

  async getDevice(id: string): Promise<VirtualDevice> {
    const res = await fetch(`${API_BASE}/devices/${id}`);
    return handleResponse<VirtualDevice>(res);
  },

  async createDevice(device: {
    id: string;
    name: string;
    type: string;
    firmwareVersion: string;
    minimumVersion: string;
    config?: any;
  }): Promise<VirtualDevice> {
    const res = await fetch(`${API_BASE}/devices`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(device),
    });
    return handleResponse<VirtualDevice>(res);
  },

  async updateDevice(id: string, patch: any): Promise<VirtualDevice> {
    const res = await fetch(`${API_BASE}/devices/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
    return handleResponse<VirtualDevice>(res);
  },

  async deleteDevice(id: string): Promise<{ ok: boolean }> {
    const res = await fetch(`${API_BASE}/devices/${id}`, { method: 'DELETE' });
    return handleResponse<{ ok: boolean }>(res);
  },

  async startDevice(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/devices/${id}/start`, { method: 'POST' });
    return handleResponse<any>(res);
  },

  async stopDevice(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/devices/${id}/stop`, { method: 'POST' });
    return handleResponse<any>(res);
  },

  // Firmware Lab
  async uploadFirmware(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('firmwareFile', file);
    const res = await fetch(`${API_BASE}/firmware/upload`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<any>(res);
  },

  async verifyFirmware(deviceId: string, fileId: string): Promise<VerificationResult> {
    const res = await fetch(`${API_BASE}/firmware/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId, fileId }),
    });
    return handleResponse<VerificationResult>(res);
  },

  async generateSamplePackage(deviceId: string, scenario: string): Promise<any> {
    const res = await fetch(`${API_BASE}/firmware/generate-sample`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId, scenario }),
    });
    return handleResponse<any>(res);
  },

  // Simulations
  async getScenarios(): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE}/simulations/scenarios`);
    return handleResponse<Record<string, any>>(res);
  },

  async runSimulation(deviceId: string, scenarioType: string): Promise<any> {
    const res = await fetch(`${API_BASE}/simulations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId, scenarioType }),
    });
    return handleResponse<any>(res);
  },

  async getSimulationHistory(): Promise<SimulationSession[]> {
    const res = await fetch(`${API_BASE}/simulations/history`);
    return handleResponse<SimulationSession[]>(res);
  },

  // Remote Attestation
  async createChallenge(deviceId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}/attestation/challenge`, { method: 'POST' });
    return handleResponse<any>(res);
  },

  async simulateAttestationReport(deviceId: string, challengeId: string, tamper: boolean = false): Promise<any> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}/attestation/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId, tamper }),
    });
    return handleResponse<any>(res);
  },

  async verifyAttestationReport(deviceId: string, challengeId: string, report: any): Promise<any> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}/attestation/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId, report }),
    });
    return handleResponse<any>(res);
  },

  // Logs
  async getLogs(params: {
    deviceId?: string;
    severity?: string;
    eventType?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; events: SecurityEvent[] }> {
    const query = new URLSearchParams();
    if (params.deviceId) query.set('deviceId', params.deviceId);
    if (params.severity) query.set('severity', params.severity);
    if (params.eventType) query.set('eventType', params.eventType);
    if (params.search) query.set('search', params.search);
    if (params.limit) query.set('limit', String(params.limit));
    if (params.offset) query.set('offset', String(params.offset));

    const res = await fetch(`${API_BASE}/logs?${query.toString()}`);
    return handleResponse<{ total: number; events: SecurityEvent[] }>(res);
  },

  // Performance Benchmarking
  async runBenchmark(iterations: number = 25, payloadSizeKb: number = 256): Promise<PerformanceBenchmark> {
    const res = await fetch(`${API_BASE}/performance/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iterations, payloadSizeKb }),
    });
    return handleResponse<PerformanceBenchmark>(res);
  },

  // Settings & Keystore
  async getSettings(): Promise<{ settings: Record<string, string>; trustedKeys: any[] }> {
    const res = await fetch(`${API_BASE}/settings`);
    return handleResponse<{ settings: Record<string, string>; trustedKeys: any[] }>(res);
  },

  async updateSettings(settings: Record<string, any>): Promise<any> {
    const res = await fetch(`${API_BASE}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings }),
    });
    return handleResponse<any>(res);
  },

  async getAnomalies(): Promise<AnomalyAlert[]> {
    const res = await fetch(`${API_BASE}/anomalies`);
    return handleResponse<AnomalyAlert[]>(res);
  },

  async acknowledgeAnomaly(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/anomalies/${id}/acknowledge`, { method: 'POST' });
    return handleResponse<any>(res);
  },

  async resetDemoData(): Promise<any> {
    const res = await fetch(`${API_BASE}/reset-demo`, { method: 'POST' });
    return handleResponse<any>(res);
  },
};
