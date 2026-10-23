export type DeviceType = 'camera' | 'environmental_sensor' | 'smart_lock' | 'router';

export type DeviceStatus = 'STOPPED' | 'RUNNING' | 'VERIFYING' | 'UPDATING' | 'HEALTHY' | 'DEGRADED' | 'UPDATE_REJECTED';

export type SecurityStatus = 'SECURE' | 'WARNING' | 'COMPROMISED';

export interface TelemetryData {
  deviceId: string;
  timestamp: string;
  cpuPercent: number;
  memoryPercent: number;
  networkKbps: number;
  uptimeSeconds: number;
  activeSensors: number;
  status: string;
  securityStatus: string;
}

export interface VirtualDevice {
  id: string;
  name: string;
  type: DeviceType;
  firmware_version: string;
  minimum_version: string;
  device_status: DeviceStatus;
  security_status: SecurityStatus;
  last_boot_time: string | null;
  last_update_time: string | null;
  boot_hash: string | null;
  trusted_key_id: string;
  config_json?: string;
  config?: Record<string, any>;
  telemetry?: TelemetryData;
  created_at: string;
}

export interface VerificationCheck {
  id: string;
  name: string;
  category: 'STRUCTURE' | 'INTEGRITY' | 'AUTHENTICITY' | 'COMPATIBILITY' | 'POLICY' | 'REPLAY';
  status: 'PASSED' | 'FAILED' | 'SKIPPED';
  detail: string;
  timestamp: string;
}

export interface VerificationResult {
  decision: 'APPROVED' | 'REJECTED';
  reason: string;
  checks: VerificationCheck[];
  manifest?: any;
  calculatedHash?: string;
  targetDeviceId: string;
  previousVersion: string;
  proposedVersion: string;
  updateId: string;
  isSimulatedDemo?: boolean;
}

export interface SecurityEvent {
  id: string;
  device_id: string | null;
  event_type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  update_id?: string | null;
  verification_result?: string | null;
  reason_code: string;
  created_at: string;
}

export interface SimulationSession {
  id: string;
  device_id: string;
  scenario_type: string;
  title: string;
  status: 'BLOCKED' | 'PASSED' | 'FAILED';
  detected_check: string;
  affected_component: string;
  potential_impact: string;
  defense_action: string;
  steps: any[];
  created_at: string;
}

export interface AnomalyAlert {
  id: string;
  device_id: string;
  category: string;
  severity: string;
  evidence: string;
  recommended_response: string;
  created_at: string;
  acknowledged: number;
}

export interface PerformanceBenchmark {
  iterations: number;
  payloadSizeKb: number;
  benchmarks: {
    sha256: { name: string; min: number; max: number; avg: number; unit: string };
    ed25519Verify: { name: string; min: number; max: number; avg: number; unit: string };
    canonicalJson: { name: string; min: number; max: number; avg: number; unit: string };
    fullPipelineEstimate: { name: string; avg: number; unit: string };
  };
  note: string;
}
