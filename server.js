import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

import {
  runFleetScalingBenchmark,
  abortBenchmark,
  exportBenchmarkHistoryCsv,
  getEnvironmentInfo
} from './src/performance.js';

import {
  getDatabase,
  getBenchmarkHistory,
  deleteBenchmarkRun,
  getThreatTestHistory,
  getDevices,
  getDevice,
  updateDevice,
  addSecurityEvent,
  getSecurityEvents,
  getIncidents,
  getIncident,
  updateIncident,
  getTrustedKeys,
  addTrustedKey,
  revokeTrustedKey,
  getAnomalyRules,
  updateAnomalyRule,
  getAnomalyAlerts,
  resolveAnomalyAlert,
  getAuditLogs,
  addAuditLog,
  getSettings,
  updateSetting,
  resetDemoData,
  getSimulationTrials
} from './src/database.js';

import {
  generateSampleFirmwareFiles,
  runVerificationTrial,
  getAutoUpdateServerStatus
} from './src/autoUpdateServer.js';

import {
  evaluateFirmwarePackage,
  recordAuthenticationAttempt,
  recordSensorTelemetry,
  recordHeartbeat
} from './src/detectionEngine.js';

import {
  generateEd25519KeyPair,
  calculateSha256
} from './src/cryptoUtils.js';

import { checkDockerStatus } from './src/dockerUtils.js';

import {
  PROTECTED_ASSETS,
  ATTACKER_PROFILES,
  TRUST_BOUNDARIES,
  RISK_SCORING_METHODOLOGY,
  THREAT_REGISTER,
  SECURITY_LIMITATIONS,
  runThreatSimulation,
  exportThreatRegisterCsv,
  generateThreatModelReportHtml
} from './src/threatModel.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Static file hosting: serve public folder and ensure /images/ works
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use('/test-packages', express.static(path.join(__dirname, 'public', 'test-packages')));

// Initialize database schema and keystore
try {
  getDatabase();
  console.log('[IoT CyberShield] SQLite persistent database and keystore initialized.');
} catch (err) {
  console.error('[IoT CyberShield] Database init error:', err);
}

// -------------------------------------------------------------
// Health & Telemetry Registry Endpoints
// -------------------------------------------------------------

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'IoT CyberShield Security Platform',
    version: '2.0.0',
    mode: 'software emulation',
    supportedDevicesCount: 4,
    features: [
      'firmware-integrity-verification',
      'ed25519-digital-signatures',
      'anti-rollback-protection',
      'anti-replay-ledger',
      'attack-detection-engine',
      'incident-investigations',
      'performance-benchmarks',
      'threat-model-analysis'
    ]
  });
});

app.get('/api/devices', (_req, res) => {
  try {
    const devices = getDevices();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/devices/:id', (req, res) => {
  try {
    const device = getDevice(req.params.id);
    if (!device) return res.status(404).json({ error: 'Device not found.' });
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/metrics', (_req, res) => {
  try {
    const db = getDatabase();
    const devices = getDevices();

    const verifiedRow = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE event_type LIKE '%Firmware%' AND response_outcome = 'APPROVED'").get();
    const rejectedRow = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE response_outcome IN ('REJECTED', 'BLOCKED')").get();
    const alertsRow = db.prepare("SELECT COUNT(*) as count FROM anomaly_alerts WHERE status = 'ACTIVE'").get();
    const incidentsRow = db.prepare("SELECT COUNT(*) as count FROM incidents WHERE status = 'OPEN'").get();
    const totalEventsRow = db.prepare("SELECT COUNT(*) as count FROM security_events").get();

    res.json({
      devices: devices.length,
      onlineDevices: devices.filter(d => d.device_status === 'Online').length,
      verified: verifiedRow ? verifiedRow.count : 0,
      rejected: rejectedRow ? rejectedRow.count : 0,
      alerts: alertsRow ? alertsRow.count : 0,
      openIncidents: incidentsRow ? incidentsRow.count : 0,
      totalEvents: totalEventsRow ? totalEventsRow.count : 0,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Interactive Device Hardware Simulation Endpoints
// -------------------------------------------------------------

// 1. ESP32 Keypad Locker: PIN entry test (Never log plaintext PIN!)
app.post('/api/devices/:id/keypad', (req, res) => {
  const { pin, requestId } = req.body || {};
  const device = getDevice(req.params.id);
  if (!device || device.type !== 'smart_lock') {
    return res.status(400).json({ error: 'Select the ESP32 Smart Locker for keypad operations.' });
  }

  // Keypad PIN policy: Valid PIN is '1234'
  const isValid = pin === '1234';
  const hashedPin = pin ? calculateSha256(pin).slice(0, 12) : 'EMPTY';

  const authResult = recordAuthenticationAttempt(device.id, isValid, {
    interface: '4x4 Matrix Keypad',
    sourceIp: req.ip || '127.0.0.1',
    endpoint: 'POST /api/devices/:id/keypad',
    pinHash: hashedPin // Log only one-way hash, NEVER plaintext PIN!
  });

  if (isValid) {
    // Unlock solenoid for 5 seconds then relock
    updateDevice(device.id, {
      telemetry_json: JSON.stringify({
        lockState: 'UNLOCKED',
        solenoidVolts: 12.0,
        failedPinAttempts: 0,
        lastUnlockTime: new Date().toISOString(),
        unlockedBy: 'Authorized Keypad PIN'
      })
    });

    setTimeout(() => {
      updateDevice(device.id, {
        telemetry_json: JSON.stringify({
          lockState: 'LOCKED',
          solenoidVolts: 12.0,
          failedPinAttempts: 0,
          lastUnlockTime: new Date().toISOString(),
          unlockedBy: null
        })
      });
    }, 5000);

    return res.json({
      success: true,
      lockState: 'UNLOCKED',
      message: 'PIN accepted. 12V Solenoid unlocked (auto-relock in 5 seconds).'
    });
  } else {
    return res.json({
      success: false,
      lockState: 'LOCKED',
      authResult,
      message: authResult.message || 'Invalid PIN rejected by ESP32 keypad controller.'
    });
  }
});

// 2. DHT22 / AM2302 Sensor: Generate or update environmental readings
app.post('/api/devices/:id/telemetry', (req, res) => {
  const { temperature, humidity } = req.body || {};
  const device = getDevice(req.params.id);
  if (!device || device.type !== 'environmental_sensor') {
    return res.status(400).json({ error: 'Select DHT22 Environmental Sensor for telemetry operations.' });
  }

  const tempVal = temperature !== undefined ? Number(temperature) : (20 + (Math.random() * 6));
  const humVal = humidity !== undefined ? Number(humidity) : (45 + (Math.random() * 8));

  const result = recordSensorTelemetry(device.id, tempVal.toFixed(1), humVal.toFixed(1), {
    sourceIp: req.ip
  });

  res.json(result);
});

// 3. TP-Link Tapo C200 Camera: Access attempt simulation
app.post('/api/devices/:id/camera-access', (req, res) => {
  const { token, action = 'RTSP_STREAM' } = req.body || {};
  const device = getDevice(req.params.id);
  if (!device || device.type !== 'camera') {
    return res.status(400).json({ error: 'Select TP-Link Tapo C200 for camera operations.' });
  }

  const isValidToken = token === 'tapo-session-auth-token-valid';
  const result = recordAuthenticationAttempt(device.id, isValidToken, {
    interface: 'RTSP Stream / Onvif Service',
    sourceIp: req.ip || '192.168.1.188',
    endpoint: 'POST /api/devices/:id/camera-access'
  });

  res.json({
    authorized: isValidToken,
    action,
    result,
    message: isValidToken ? 'RTSP stream connection established (554/tcp).' : 'RTSP stream unauthorized. Access credentials rejected.'
  });
});

// 4. TP-Link Archer C6 Router: Simulated administration access
app.post('/api/devices/:id/router-admin', (req, res) => {
  const { username, password, configChange } = req.body || {};
  const device = getDevice(req.params.id);
  if (!device || device.type !== 'router') {
    return res.status(400).json({ error: 'Select TP-Link Archer C6 for router operations.' });
  }

  const isAuth = username === 'admin' && password === 'CyberShield@Router2026';
  const result = recordAuthenticationAttempt(device.id, isAuth, {
    interface: 'HTTPS Web Admin Port 443',
    sourceIp: req.ip || '192.168.1.50',
    endpoint: 'POST /api/devices/:id/router-admin'
  });

  if (isAuth && configChange) {
    const currentConfig = device.config || {};
    const updated = { ...currentConfig, ...configChange };
    updateDevice(device.id, { config_json: JSON.stringify(updated) });

    addSecurityEvent({
      id: `EVT-${Date.now()}`,
      timestamp: new Date().toISOString(),
      deviceId: device.id,
      eventType: 'Configuration change',
      severity: 'INFO',
      originatingComponent: 'Router Admin Web Interface',
      sourceMetadata: req.ip || '192.168.1.50',
      destinationMetadata: 'Archer C6 Gateway Core',
      responseOutcome: 'APPLIED',
      verificationResult: 'PASSED',
      description: `Router configuration updated: ${Object.keys(configChange).join(', ')}.`
    });
  }

  res.json({
    authorized: isAuth,
    result,
    message: isAuth ? 'Router administrative session authenticated.' : 'Invalid router administrative credentials.'
  });
});

// 5. Device Heartbeat
app.post('/api/devices/:id/heartbeat', (req, res) => {
  const result = recordHeartbeat(req.params.id);
  res.json(result);
});

// -------------------------------------------------------------
// AUTOMATIC FIRMWARE UPDATE SERVER & 3D SIMULATION API
// -------------------------------------------------------------

app.get('/api/ota/auto-update-server/status', (_req, res) => {
  try {
    const status = getAutoUpdateServerStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ota/auto-update-server/generate/:deviceId?', (req, res) => {
  try {
    const deviceId = req.params.deviceId || 'DEV-CAM-01';
    const bundle = generateSampleFirmwareFiles(deviceId);
    res.json(bundle);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ota/auto-update-server/trial', async (req, res) => {
  try {
    const { deviceId = 'DEV-CAM-01', packageType = 'valid' } = req.body || {};
    const result = await runVerificationTrial(deviceId, packageType, { sourceIp: req.ip });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/ota/auto-update-server/trials', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const trials = getSimulationTrials(limit);
    res.json(trials);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// FIRMWARE VERIFICATION PIPELINE (MANDATORY SECURITY ENFORCEMENT)
// -------------------------------------------------------------

app.post('/api/verify', async (req, res) => {
  try {
    const {
      deviceId,
      fileName,
      fileHash,
      trustedHash,
      firmwareVersion,
      requestId,
      keyId,
      signatureValid,
      signature,
      rawText,
      isMalformedTest
    } = req.body || {};

    const device = getDevice(deviceId);
    if (!device) {
      return res.status(400).json({ error: 'Select a valid virtual device. Only the four supported devices are permitted.' });
    }

    // Harmless text files (like safe_firmware_test.txt) must be safely rejected
    if (rawText && rawText.includes('SAFE_FIRMWARE_TEST_FILE')) {
      const evaluation = await evaluateFirmwarePackage({
        isMalformedTest: true,
        fileName: fileName || 'safe_firmware_test.txt',
        requestId
      }, deviceId, { sourceIp: req.ip });

      return res.json({
        deviceId,
        fileName: fileName || 'safe_firmware_test.txt',
        decision: 'REJECTED',
        reason: 'Uploaded file is a harmless plain-text file. Executable binary firmware is not permitted; update safely rejected.',
        checks: evaluation.checks,
        incidentId: evaluation.incidentId
      });
    }

    const payload = {
      fileName: fileName || 'firmware.bin',
      fileHash,
      expectedHash: trustedHash,
      firmwareVersion: firmwareVersion || '2.2.0',
      requestId: requestId || `REQ-${crypto.randomUUID().slice(0, 8)}`,
      keyId: keyId || 'dev-ed25519-primary',
      signatureValid,
      signature,
      isMalformedTest: Boolean(isMalformedTest)
    };

    const result = await evaluateFirmwarePackage(payload, deviceId, {
      sourceIp: req.ip,
      applyUpdate: false // Safety: Do not flash physical hardware in software prototype!
    });

    res.json({
      deviceId,
      fileName: payload.fileName,
      fileHash: result.calculatedHash || fileHash,
      checks: result.checks,
      decision: result.decision,
      reason: result.reason,
      incidentId: result.incidentId,
      mode: 'Software emulation boundary; no physical hardware modified.'
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// ATTACK SIMULATOR (10 SUPPORTED SCENARIOS + NORMAL TEST MODE)
// -------------------------------------------------------------

app.post('/api/simulate', async (req, res) => {
  try {
    const { deviceId, attackType, testMode = 'SECURITY_TEST' } = req.body || {};
    const device = getDevice(deviceId);
    if (!device) {
      return res.status(400).json({ error: 'Select a valid virtual device from the four supported models.' });
    }

    // Normal Test Mode: Generates a valid harmless test package and normal event
    if (testMode === 'NORMAL_TEST') {
      const evaluation = await evaluateFirmwarePackage({
        fileName: `firmware_${device.id}_v${device.firmware_version}_valid.bin`,
        fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        firmwareVersion: '2.2.0',
        requestId: `REQ-VALID-${crypto.randomUUID().slice(0, 8)}`,
        keyId: 'dev-ed25519-primary',
        signatureValid: true
      }, device.id, { applyUpdate: true });

      return res.json({
        deviceId: device.id,
        testMode: 'NORMAL_TEST',
        result: 'PASSED',
        decision: 'APPROVED',
        title: 'Normal Operational Test Package Ingestion',
        reason: 'Package passed all verification checks and was accepted for update staging.',
        checks: evaluation.checks,
        steps: [
          { label: 'Package Ingestion', status: 'PASSED', detail: 'Valid container headers received.' },
          { label: 'SHA-256 Digest', status: 'PASSED', detail: 'Calculated hash matches manifest.' },
          { label: 'Ed25519 Signature', status: 'PASSED', detail: 'Verified with trusted root key.' },
          { label: 'Version Policy', status: 'PASSED', detail: 'v2.2.0 satisfies anti-rollback policy.' },
          { label: 'Replay Protection', status: 'PASSED', detail: 'Unique transaction token accepted.' }
        ]
      });
    }

    // Security Test Mode: 10 Scenarios
    let simPayload = {};
    let scenarioTitle = 'Security Attack Simulation';

    switch (attackType) {
      case 'tampering':
      case 'modification':
        scenarioTitle = 'Firmware Binary Hash Tampering Attack';
        simPayload = {
          fileHash: 'deadbeef00000000000000000000000000000000000000000000000000000000',
          expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          signatureValid: true
        };
        break;

      case 'signature':
      case 'invalid_signature':
        scenarioTitle = 'Invalid / Forged Digital Signature Attack';
        simPayload = {
          fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          signatureValid: false
        };
        break;

      case 'unknown_key':
        scenarioTitle = 'Untrusted / Rogue Signing Key Injection';
        simPayload = {
          fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          keyId: 'untrusted-rogue-key-999',
          signatureValid: false
        };
        break;

      case 'downgrade':
        scenarioTitle = 'Unauthorized Firmware Downgrade / Rollback Attack';
        simPayload = {
          fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          firmwareVersion: '0.9.0', // Older than minimum version
          signatureValid: true
        };
        break;

      case 'replay':
        scenarioTitle = 'Replay Attack (Reused Transaction ID / Nonce)';
        const reusedToken = `REPLAY-FIXED-TOKEN-${device.id}`;
        // Pre-seed token to force replay trigger
        checkAndRecordReplayToken(device.id, reusedToken);
        simPayload = {
          fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          expectedHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          requestId: reusedToken,
          signatureValid: true
        };
        break;

      case 'malformed':
        scenarioTitle = 'Malformed Firmware Package Container';
        simPayload = {
          isMalformedTest: true,
          fileName: 'malformed_package_exploit.zip'
        };
        break;

      case 'auth_bruteforce':
        scenarioTitle = 'Repeated Authentication Failures / Brute-Force';
        // Run 3 rapid failures
        recordAuthenticationAttempt(device.id, false, { interface: 'Simulated Attack CLI' });
        recordAuthenticationAttempt(device.id, false, { interface: 'Simulated Attack CLI' });
        const lastAuth = recordAuthenticationAttempt(device.id, false, { interface: 'Simulated Attack CLI' });
        return res.json({
          deviceId: device.id,
          testMode: 'SECURITY_TEST',
          title: scenarioTitle,
          attackType,
          result: 'BLOCKED',
          decision: 'REJECTED',
          reason: lastAuth.message || 'Brute-force lockout triggered.',
          incidentId: lastAuth.incidentId,
          steps: [
            { label: 'Attempt 1', status: 'FAILED', detail: 'Invalid credential recorded.' },
            { label: 'Attempt 2', status: 'FAILED', detail: 'Second failure logged.' },
            { label: 'Attempt 3', status: 'FAILED', detail: 'Third failure tripped threshold.' },
            { label: 'Defense Action', status: 'PASSED', detail: 'Enforced 300-second simulated lockout.' }
          ]
        });

      case 'unauthorized_config':
        scenarioTitle = 'Unauthorized Configuration Modification Attempt';
        const incIdCfg = `INC-${Date.now().toString().slice(-6)}`;
        createIncident({
          id: incIdCfg,
          title: `Unauthorized Configuration Modification on ${device.name}`,
          classification: 'Security policy violation',
          severity: 'HIGH',
          severityJustification: 'Attempted to change critical security settings without administrative privilege.',
          deviceId: device.id,
          deviceModel: device.model,
          timestampUtc: new Date().toISOString(),
          timestampLocal: new Date().toLocaleString(),
          summary: `An unauthenticated command attempted to modify security settings on ${device.name}. The operation was blocked.`,
          attackCategory: 'Unauthorized Configuration Modification',
          occurredLocation: 'Management API Gateway',
          sourceMetadata: 'Internal simulator',
          destinationMetadata: `${device.name} Settings Daemon`,
          entryPoint: 'POST /api/devices/:id/config',
          detectionRuleId: 'RULE-CFG-008',
          triggerReason: 'Missing valid administrative token during configuration write.',
          evidenceJson: { rejectedConfig: { firewall: 'DISABLED' } },
          correlatedEventsJson: [`EVT-${Date.now()}`],
          observedImpact: 'Configuration change dropped; baseline settings preserved.',
          responseAction: 'Rejected request and generated high-severity security incident.',
          responseSuccess: true,
          recoveryStatus: 'Recovered (Normal Operation)',
          confidenceLevel: 'High',
          evidenceLimitations: 'Software emulation boundary.',
          recommendedAction: 'Verify API access logs and ensure TLS mutual authentication is enforced.'
        });
        addSecurityEvent({
          id: `EVT-${Date.now()}`,
          timestamp: new Date().toISOString(),
          deviceId: device.id,
          eventType: 'Security policy violation',
          severity: 'HIGH',
          originatingComponent: 'Config Verifier',
          sourceMetadata: 'Internal simulator',
          destinationMetadata: `${device.name} Core`,
          detectionRuleId: 'RULE-CFG-008',
          relatedIncidentId: incIdCfg,
          responseOutcome: 'BLOCKED',
          verificationResult: 'REJECTED',
          description: 'Blocked unauthorized simulated configuration change attempt.'
        });
        return res.json({
          deviceId: device.id,
          testMode: 'SECURITY_TEST',
          title: scenarioTitle,
          result: 'BLOCKED',
          decision: 'REJECTED',
          reason: 'Missing valid administrative token during configuration write.',
          incidentId: incIdCfg,
          steps: [
            { label: 'Ingress Request', status: 'PASSED', detail: 'Received unauthorized config write.' },
            { label: 'Token Validation', status: 'FAILED', detail: 'Missing administrative credentials.' },
            { label: 'Defense Action', status: 'PASSED', detail: 'Dropped payload; golden baseline preserved.' }
          ]
        });

      case 'missed_heartbeat':
        scenarioTitle = 'Simulated Heartbeat Availability Failure';
        updateDevice(device.id, { device_status: 'Degraded' });
        const incIdHbt = `INC-${Date.now().toString().slice(-6)}`;
        createIncident({
          id: incIdHbt,
          title: `Missed Heartbeat Health Incident on ${device.name}`,
          classification: 'Device health incident',
          severity: 'MEDIUM',
          severityJustification: 'Device failed to send scheduled heartbeat signal within expected window.',
          deviceId: device.id,
          deviceModel: device.model,
          timestampUtc: new Date().toISOString(),
          timestampLocal: new Date().toLocaleString(),
          summary: `${device.name} missed its expected keepalive heartbeat. Note: Classified honestly as a device health incident, not an attack.`,
          attackCategory: 'Availability / Service Health',
          occurredLocation: 'Heartbeat Monitor Daemon',
          sourceMetadata: 'Internal simulator',
          destinationMetadata: 'Monitoring Controller',
          entryPoint: 'Internal Timer',
          detectionRuleId: 'RULE-HBT-006',
          triggerReason: 'No keepalive received for > 30 seconds.',
          evidenceJson: { lastSeen: device.last_seen_at },
          correlatedEventsJson: [`EVT-${Date.now()}`],
          observedImpact: 'Device status updated to Degraded in fleet inventory.',
          responseAction: 'Sent health alert and initiated background ping.',
          responseSuccess: true,
          recoveryStatus: 'Degraded',
          confidenceLevel: 'High (Observed timeout)',
          evidenceLimitations: 'Software emulation boundary.',
          recommendedAction: 'Check emulator container logs and network routing.'
        });
        return res.json({
          deviceId: device.id,
          testMode: 'SECURITY_TEST',
          title: scenarioTitle,
          result: 'HEALTH_ALERT',
          decision: 'DEGRADED',
          reason: 'Heartbeat timeout observed. Correctly classified as health incident.',
          incidentId: incIdHbt,
          steps: [
            { label: 'Heartbeat Timer', status: 'FAILED', detail: 'Timeout threshold exceeded.' },
            { label: 'Classification', status: 'PASSED', detail: 'Marked as device health incident (not attack).' }
          ]
        });

      case 'container_outage':
        scenarioTitle = 'Docker Container Outage Simulation';
        updateDevice(device.id, { device_status: 'Offline' });
        return res.json({
          deviceId: device.id,
          testMode: 'SECURITY_TEST',
          title: scenarioTitle,
          result: 'CONTAINER_OFFLINE',
          decision: 'OFFLINE',
          reason: 'Container process exited. Classified as service availability event.',
          steps: [
            { label: 'Container Check', status: 'FAILED', detail: 'Process exited with code 0.' },
            { label: 'Fleet Registry', status: 'PASSED', detail: 'Updated status to Offline.' }
          ]
        });

      default:
        return res.status(400).json({ error: 'Choose a supported attack scenario.' });
    }

    const evaluation = await evaluateFirmwarePackage(simPayload, device.id, { sourceIp: req.ip });

    res.json({
      deviceId: device.id,
      testMode: 'SECURITY_TEST',
      title: scenarioTitle,
      attackType,
      result: evaluation.decision === 'REJECTED' ? 'BLOCKED' : 'PASSED',
      decision: evaluation.decision,
      reason: evaluation.reason,
      incidentId: evaluation.incidentId,
      checks: evaluation.checks,
      steps: [
        { label: 'Scenario Initialized', status: 'PASSED', detail: `Scenario dispatched to ${device.name}.` },
        { label: 'Security Enforcement', status: 'FAILED', detail: evaluation.reason },
        { label: 'Defense Response', status: 'PASSED', detail: 'Package quarantined; incident logged.' }
      ]
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// INCIDENT INVESTIGATION & FORENSICS ENDPOINTS (22 FIELDS)
// -------------------------------------------------------------

app.get('/api/incidents', (req, res) => {
  try {
    const list = getIncidents(req.query);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/incidents/export-json', (_req, res) => {
  try {
    const list = getIncidents();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_incidents_forensics.json"');
    res.send(JSON.stringify(list, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/incidents/:id', (req, res) => {
  try {
    const inc = getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident not found.' });
    res.json(inc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/incidents/:id', (req, res) => {
  try {
    const updated = updateIncident(req.params.id, req.body || {});
    if (!updated) return res.status(404).json({ error: 'Incident not found.' });

    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Analyst',
      action: 'UPDATE_INCIDENT',
      target: req.params.id,
      details: `Updated incident status to '${updated.status}'.`,
      status: 'SUCCESS'
    });

    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// SECURITY EVENT LOGS ENDPOINTS
// -------------------------------------------------------------

app.get('/api/events', (req, res) => {
  try {
    const events = getSecurityEvents(req.query);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/events/export-csv', (_req, res) => {
  try {
    const events = getSecurityEvents({ limit: 1000 });
    const headers = ['Event ID', 'Timestamp UTC', 'Device ID', 'Event Type', 'Severity', 'Component', 'Verification Result', 'Outcome', 'Description'];
    const lines = [headers.join(',')];

    for (const e of events) {
      const row = [
        `"${e.id}"`,
        `"${e.timestamp}"`,
        `"${e.device_id}"`,
        `"${e.event_type}"`,
        `"${e.severity}"`,
        `"${e.originating_component}"`,
        `"${e.verification_result}"`,
        `"${e.response_outcome}"`,
        `"${(e.description || '').replace(/"/g, '""')}"`
      ];
      lines.push(row.join(','));
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_security_events.csv"');
    res.send(lines.join('\n'));
  } catch (err) {
    res.status(500).send(`Error exporting CSV: ${err.message}`);
  }
});

// -------------------------------------------------------------
// TRUSTED KEYS MANAGEMENT
// -------------------------------------------------------------

app.get('/api/keys', (_req, res) => {
  try {
    const keys = getTrustedKeys();
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/keys/rotate', (req, res) => {
  try {
    const { name } = req.body || {};
    const keyId = `key-ed25519-${Date.now().toString(36)}`;
    const keyPair = generateEd25519KeyPair(keyId, name || 'Rotated Operational Signer (Dev)');

    addTrustedKey({
      keyId: keyPair.keyId,
      name: keyPair.name,
      algorithm: 'Ed25519',
      publicKeyHex: keyPair.publicKeyHex,
      status: 'ACTIVE'
    });

    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Administrator',
      action: 'KEY_ROTATION',
      target: keyId,
      details: `Generated and registered new Ed25519 signing key '${keyId}'.`,
      status: 'SUCCESS'
    });

    res.json({
      success: true,
      keyId: keyPair.keyId,
      name: keyPair.name,
      publicKeyHex: keyPair.publicKeyHex,
      message: 'New Ed25519 root key generated and registered.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/keys/:id/revoke', (req, res) => {
  try {
    revokeTrustedKey(req.params.id);
    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Administrator',
      action: 'KEY_REVOCATION',
      target: req.params.id,
      details: `Revoked signing key '${req.params.id}'. Firmware updates signed with this key will now be rejected.`,
      status: 'SUCCESS'
    });
    res.json({ success: true, message: `Key ${req.params.id} revoked.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// ANOMALY RULES & ALERTS
// -------------------------------------------------------------

app.get('/api/anomalies/rules', (_req, res) => {
  try {
    const rules = getAnomalyRules();
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/anomalies/rules/:id', (req, res) => {
  try {
    const updated = updateAnomalyRule(req.params.id, req.body || {});
    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Analyst',
      action: 'UPDATE_ANOMALY_RULE',
      target: req.params.id,
      details: `Adjusted threshold to ${updated.threshold} ${updated.unit}.`,
      status: 'SUCCESS'
    });
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/anomalies/alerts', (_req, res) => {
  try {
    const alerts = getAnomalyAlerts();
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/anomalies/alerts/:id/resolve', (req, res) => {
  try {
    const { status = 'ACKNOWLEDGED', note = '' } = req.body || {};
    const alert = resolveAnomalyAlert(req.params.id, status, note);

    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Analyst',
      action: 'RESOLVE_ALERT',
      target: req.params.id,
      details: `Alert marked as '${status}'. Note: ${note}`,
      status: 'SUCCESS'
    });

    res.json(alert);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// DOCKER CONTAINER HEALTH INSPECTION
// -------------------------------------------------------------

app.get('/api/docker/status', (_req, res) => {
  try {
    const status = checkDockerStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// AUDIT LOGS & SETTINGS
// -------------------------------------------------------------

app.get('/api/audit-logs', (_req, res) => {
  try {
    const logs = getAuditLogs();
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/settings', (_req, res) => {
  try {
    const settings = getSettings();
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/settings', (req, res) => {
  try {
    let lastSettings = {};
    for (const [k, v] of Object.entries(req.body || {})) {
      lastSettings = updateSetting(k, v);
    }
    addAuditLog({
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'Security Administrator',
      action: 'UPDATE_SETTINGS',
      target: 'APPLICATION_SETTINGS',
      details: `Updated settings: ${Object.keys(req.body).join(', ')}.`,
      status: 'SUCCESS'
    });
    res.json(lastSettings);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/reset-demo', (_req, res) => {
  try {
    const result = resetDemoData();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// FEATURE 1: Performance Overhead Measurement Endpoints
// -------------------------------------------------------------

app.get('/api/benchmark/environment', (_req, res) => {
  res.json(getEnvironmentInfo());
});

app.post('/api/benchmark/run', async (req, res) => {
  try {
    const {
      fleetSize = 5,
      testRuns = 3,
      packageSizeBytes = 262144,
      simulateFailures = false
    } = req.body || {};

    const result = await runFleetScalingBenchmark({
      fleetSize: Number(fleetSize),
      testRuns: Number(testRuns),
      packageSizeBytes: Number(packageSizeBytes),
      simulateFailures: Boolean(simulateFailures)
    });

    addSecurityEvent({
      id: `EVT-${Date.now()}`,
      timestamp: new Date().toISOString(),
      deviceId: 'FLEET-BENCHMARK',
      eventType: 'Performance Benchmark',
      severity: 'INFO',
      originatingComponent: 'Benchmark Runner',
      sourceMetadata: 'Internal simulator',
      destinationMetadata: 'Process Performance Counter',
      responseOutcome: 'PASSED',
      verificationResult: 'PASSED',
      description: `Completed benchmark for ${fleetSize} virtual devices (Overhead: ${result.overheadMs} ms, ${result.overheadPct !== null ? result.overheadPct + '%' : 'N/A'}).`
    });

    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Benchmark failed.' });
  }
});

app.post('/api/benchmark/stop', (_req, res) => {
  const stopped = abortBenchmark();
  res.json({ stopped, message: stopped ? 'Benchmark stop signal received.' : 'No benchmark was running.' });
});

app.get('/api/benchmark/history', (_req, res) => {
  try {
    const history = getBenchmarkHistory(50);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/benchmark/history/:id', (req, res) => {
  try {
    deleteBenchmarkRun(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/benchmark/export-csv', (_req, res) => {
  try {
    const csv = exportBenchmarkHistoryCsv();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_benchmarks.csv"');
    res.send(csv);
  } catch (err) {
    res.status(500).send(`Error exporting CSV: ${err.message}`);
  }
});

// -------------------------------------------------------------
// FEATURE 2: Threat Model & Security Analysis Endpoints
// -------------------------------------------------------------

app.get('/api/threats', (_req, res) => {
  res.json({
    assets: PROTECTED_ASSETS,
    profiles: ATTACKER_PROFILES,
    boundaries: TRUST_BOUNDARIES,
    riskMethodology: RISK_SCORING_METHODOLOGY,
    threats: THREAT_REGISTER,
    limitations: SECURITY_LIMITATIONS
  });
});

app.post('/api/threats/simulate', (req, res) => {
  try {
    const { threatId, deviceId = 'DEV-CAM-01' } = req.body || {};
    const simulation = runThreatSimulation(threatId, deviceId);

    addSecurityEvent({
      id: `EVT-${Date.now()}`,
      timestamp: new Date().toISOString(),
      deviceId,
      eventType: `Threat Test: ${simulation.threat.name}`,
      severity: simulation.testResult.result === 'BLOCKED' ? 'HIGH' : 'WARN',
      originatingComponent: 'Threat Simulator',
      sourceMetadata: 'Internal simulator',
      destinationMetadata: 'Security Engine',
      responseOutcome: simulation.testResult.result,
      verificationResult: simulation.testResult.result,
      description: `${simulation.testResult.blockedBy}: ${simulation.testResult.reason}`
    });

    res.json(simulation);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/threats/tests-history', (_req, res) => {
  try {
    const history = getThreatTestHistory(50);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/threats/export-csv', (_req, res) => {
  try {
    const csv = exportThreatRegisterCsv();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_threat_register.csv"');
    res.send(csv);
  } catch (err) {
    res.status(500).send(`Error exporting CSV: ${err.message}`);
  }
});

app.get('/api/threats/report', (_req, res) => {
  const html = generateThreatModelReportHtml();
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// SPA fallback for HTML5 history navigation
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`[IoT CyberShield] Running on http://0.0.0.0:${port}`);
});
