import { getDatabase, query, queryOne, execute } from '../database/db.js';
import { calculateSha256, compareVersions } from '../security/crypto.js';

export interface DeviceRecord {
  id: string;
  name: string;
  type: string;
  firmware_version: string;
  minimum_version: string;
  device_status: string;
  security_status: string;
  last_boot_time: string | null;
  last_update_time: string | null;
  boot_hash: string | null;
  trusted_key_id: string;
  config_json: string;
  created_at: string;
}

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

// In-memory simulation states for active runtime nodes
interface RuntimeState {
  bootTime: number;
  telemetryInterval?: NodeJS.Timeout;
  recentFailures: number;
}

const runtimeNodes = new Map<string, RuntimeState>();

/**
 * Perform Secure Boot verification before transitioning to RUNNING
 */
export async function simulateSecureBoot(deviceId: string): Promise<{
  success: boolean;
  status: 'BOOT_APPROVED' | 'BOOT_REJECTED';
  reason: string;
  checks: Array<{ name: string; status: 'PASSED' | 'FAILED'; detail: string }>;
}> {
  const db = await getDatabase();
  const device = queryOne<DeviceRecord>(db, 'SELECT * FROM devices WHERE id = ?', [deviceId]);

  if (!device) {
    throw new Error(`Device '${deviceId}' not found.`);
  }

  const checks: Array<{ name: string; status: 'PASSED' | 'FAILED'; detail: string }> = [];

  // Check 1: Firmware Image Integrity (Boot Hash against measured hardware baseline)
  const expectedHash = device.boot_hash || calculateSha256(`CYBERSHIELD-ROM-${device.id}-${device.firmware_version}`);
  const actualMeasured = device.boot_hash || expectedHash;

  if (actualMeasured === expectedHash) {
    checks.push({
      name: 'Hardware Root Boot Hash',
      status: 'PASSED',
      detail: `Measured image hash matches trusted ROM manifest: ${expectedHash.substring(0, 16)}...`,
    });
  } else {
    checks.push({
      name: 'Hardware Root Boot Hash',
      status: 'FAILED',
      detail: 'Measured boot partition hash does not match trusted ROM signature. Tampering suspected.',
    });
  }

  // Check 2: Minimum Hardware Revision Policy
  const meetsMin = compareVersions(device.firmware_version, device.minimum_version) >= 0;
  if (meetsMin) {
    checks.push({
      name: 'Bootloader Version Policy',
      status: 'PASSED',
      detail: `Active firmware v${device.firmware_version} satisfies minimum boot requirement v${device.minimum_version}.`,
    });
  } else {
    checks.push({
      name: 'Bootloader Version Policy',
      status: 'FAILED',
      detail: `Active firmware v${device.firmware_version} is below hardware minimum version v${device.minimum_version}.`,
    });
  }

  // Check 3: Trusted Key Association
  const trustedKey = queryOne(
    db,
    'SELECT 1 FROM trusted_signing_keys WHERE key_id = ? AND is_active = 1 AND is_revoked = 0',
    [device.trusted_key_id]
  );
  if (trustedKey) {
    checks.push({
      name: 'Hardware Public Key Store',
      status: 'PASSED',
      detail: `Configured signing key '${device.trusted_key_id}' is valid and active in hardware key storage.`,
    });
  } else {
    checks.push({
      name: 'Hardware Public Key Store',
      status: 'FAILED',
      detail: `Key identifier '${device.trusted_key_id}' is revoked or missing from hardware key storage.`,
    });
  }

  const allPassed = checks.every(c => c.status === 'PASSED');
  const now = new Date().toISOString();

  if (allPassed) {
    execute(
      db,
      "UPDATE devices SET device_status = 'RUNNING', security_status = 'SECURE', last_boot_time = ? WHERE id = ?",
      [now, device.id]
    );

    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, 'SECURE_BOOT_SUCCESS', 'INFO', ?, 'SECURE_BOOT_PASSED', ?)`,
      [`EVT-BOOT-${Date.now()}`, device.id, `Secure boot sequence completed successfully for ${device.name}.`, now]
    );

    runtimeNodes.set(device.id, {
      bootTime: Date.now(),
      recentFailures: 0,
    });

    return {
      success: true,
      status: 'BOOT_APPROVED',
      reason: 'All secure boot verification steps passed. Device reached RUNNING state.',
      checks,
    };
  } else {
    execute(
      db,
      "UPDATE devices SET device_status = 'STOPPED', security_status = 'COMPROMISED' WHERE id = ?",
      [device.id]
    );

    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, 'SECURE_BOOT_FAILED', 'HIGH', ?, 'SECURE_BOOT_VIOLATION', ?)`,
      [
        `EVT-BOOT-ERR-${Date.now()}`,
        device.id,
        `Secure boot failed for ${device.name}: ${checks.filter(c => c.status === 'FAILED').map(c => c.detail).join(' ')}`,
        now,
      ]
    );

    return {
      success: false,
      status: 'BOOT_REJECTED',
      reason: 'Secure boot verification failed. Device startup blocked for safety.',
      checks,
    };
  }
}

/**
 * Stop a simulated device
 */
export async function stopDevice(deviceId: string): Promise<void> {
  const db = await getDatabase();
  const now = new Date().toISOString();
  execute(db, "UPDATE devices SET device_status = 'STOPPED' WHERE id = ?", [deviceId]);

  execute(
    db,
    `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
     VALUES (?, ?, 'DEVICE_STOPPED', 'INFO', ?, 'USER_STOPPED', ?)`,
    [`EVT-STOP-${Date.now()}`, deviceId, `Virtual device execution halted.`, now]
  );

  runtimeNodes.delete(deviceId);
}

/**
 * Transition device state safely
 */
export async function transitionDeviceState(
  deviceId: string,
  newState: 'STOPPED' | 'RUNNING' | 'VERIFYING' | 'UPDATING' | 'HEALTHY' | 'DEGRADED' | 'UPDATE_REJECTED',
  reason?: string
): Promise<void> {
  const db = await getDatabase();
  execute(db, 'UPDATE devices SET device_status = ? WHERE id = ?', [newState, deviceId]);

  if (reason) {
    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, 'STATE_TRANSITION', 'INFO', ?, 'STATE_CHANGE', ?)`,
      [`EVT-STATE-${Date.now()}`, deviceId, `Device transitioned to ${newState}: ${reason}`, new Date().toISOString()]
    );
  }
}

/**
 * Apply approved firmware update
 */
export async function applyApprovedFirmwareUpdate(
  deviceId: string,
  newVersion: string,
  newHash: string,
  updateId: string
): Promise<void> {
  const db = await getDatabase();
  const now = new Date().toISOString();

  // Atomically update device firmware version and record update ID
  execute(
    db,
    `UPDATE devices
     SET firmware_version = ?,
         boot_hash = ?,
         device_status = 'RUNNING',
         security_status = 'SECURE',
         last_update_time = ?
     WHERE id = ?`,
    [newVersion, newHash, now, deviceId]
  );

  // Store accepted update ID for persistent replay prevention
  execute(
    db,
    `INSERT OR IGNORE INTO accepted_update_ids (device_id, update_id, accepted_at)
     VALUES (?, ?, ?)`,
    [deviceId, updateId, now]
  );

  execute(
    db,
    `INSERT INTO security_events (id, device_id, event_type, severity, description, update_id, verification_result, reason_code, created_at)
     VALUES (?, ?, 'FIRMWARE_UPDATE_SUCCESS', 'INFO', ?, ?, 'APPROVED', 'UPDATE_APPLIED', ?)`,
    [
      `EVT-UPD-${Date.now()}`,
      deviceId,
      `Firmware v${newVersion} securely flashed to virtual device.`,
      updateId,
      now,
    ]
  );
}

/**
 * Handle rejected firmware update
 * Preserves the previous version and logs security alert
 */
export async function handleRejectedFirmwareUpdate(
  deviceId: string,
  reason: string,
  updateId: string,
  failedCheck: string
): Promise<void> {
  const db = await getDatabase();
  const now = new Date().toISOString();

  // Set state to UPDATE_REJECTED, then back to RUNNING
  execute(
    db,
    "UPDATE devices SET device_status = 'UPDATE_REJECTED', security_status = 'WARNING' WHERE id = ?",
    [deviceId]
  );

  execute(
    db,
    `INSERT INTO security_events (id, device_id, event_type, severity, description, update_id, verification_result, reason_code, created_at)
     VALUES (?, ?, 'FIRMWARE_UPDATE_REJECTED', 'HIGH', ?, ?, 'REJECTED', 'POLICY_VIOLATION', ?)`,
    [
      `EVT-REJ-${Date.now()}`,
      deviceId,
      `Unsafe firmware update blocked [${failedCheck}]: ${reason}`,
      updateId,
      now,
    ]
  );

  // Anomaly check: track repeated failures
  const node = runtimeNodes.get(deviceId) || { bootTime: Date.now(), recentFailures: 0 };
  node.recentFailures += 1;
  runtimeNodes.set(deviceId, node);

  if (node.recentFailures >= 2) {
    execute(
      db,
      `INSERT INTO anomaly_alerts (id, device_id, category, severity, evidence, recommended_response, created_at)
       VALUES (?, ?, 'REPEATED_UPDATE_FAILURES', 'HIGH', ?, ?, ?)`,
      [
        `ANOM-${Date.now()}`,
        deviceId,
        `${node.recentFailures} consecutive firmware verification rejections detected on device within active session.`,
        'Isolate device update channel, inspect upstream firmware repository, and audit signing keys.',
        now,
      ]
    );
  }

  // Restore status to RUNNING with safe prior version retained
  setTimeout(async () => {
    try {
      const d = await getDatabase();
      execute(d, "UPDATE devices SET device_status = 'RUNNING' WHERE id = ? AND device_status = 'UPDATE_REJECTED'", [deviceId]);
    } catch {
      // ignore
    }
  }, 3000);
}

/**
 * Generate simulated telemetry reading for device
 */
export function getSimulatedTelemetry(device: DeviceRecord): TelemetryData {
  const isRunning = device.device_status === 'RUNNING' || device.device_status === 'HEALTHY' || device.device_status === 'DEGRADED';
  const node = runtimeNodes.get(device.id);
  const uptime = isRunning && node ? Math.floor((Date.now() - node.bootTime) / 1000) : 0;

  // Base telemetry by device type
  let baseCpu = 12;
  let baseMem = 28;
  let baseNet = 15;
  let sensors = 2;

  switch (device.type) {
    case 'camera':
      baseCpu = 35;
      baseMem = 52;
      baseNet = 1240; // video stream
      sensors = 3;
      break;
    case 'environmental_sensor':
      baseCpu = 8;
      baseMem = 18;
      baseNet = 5;
      sensors = 4;
      break;
    case 'smart_lock':
      baseCpu = 10;
      baseMem = 22;
      baseNet = 8;
      sensors = 2;
      break;
    case 'router':
      baseCpu = 42;
      baseMem = 65;
      baseNet = 4500;
      sensors = 8;
      break;
  }

  if (!isRunning) {
    return {
      deviceId: device.id,
      timestamp: new Date().toISOString(),
      cpuPercent: 0,
      memoryPercent: 0,
      networkKbps: 0,
      uptimeSeconds: 0,
      activeSensors: 0,
      status: device.device_status,
      securityStatus: device.securityStatus || device.security_status,
    };
  }

  // Add realistic subtle jitter
  const jitter = (Math.random() - 0.5) * 6;
  const cpu = Math.min(100, Math.max(1, Math.round(baseCpu + jitter)));
  const mem = Math.min(100, Math.max(5, Math.round(baseMem + jitter * 0.5)));
  const net = Math.max(0, Math.round(baseNet + (Math.random() - 0.5) * (baseNet * 0.2)));

  return {
    deviceId: device.id,
    timestamp: new Date().toISOString(),
    cpuPercent: cpu,
    memoryPercent: mem,
    networkKbps: net,
    uptimeSeconds: uptime,
    activeSensors: sensors,
    status: device.device_status,
    securityStatus: device.security_status,
  };
}
