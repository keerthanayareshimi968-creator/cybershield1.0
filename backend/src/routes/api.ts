import express, { Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { getDatabase, query, queryOne, execute, queryScalar } from '../database/db.js';
import { calculateSha256, canonicalizeJson, verifyEd25519, signEd25519, getDevPrivateKey } from '../security/crypto.js';
import { validateAndVerifyFirmware } from '../security/packageValidator.js';
import { generateFirmwarePackage } from '../services/packageGenerator.js';
import {
  simulateSecureBoot,
  stopDevice,
  applyApprovedFirmwareUpdate,
  handleRejectedFirmwareUpdate,
  getSimulatedTelemetry,
} from '../simulator/deviceSimulator.js';
import {
  createAttestationChallenge,
  generateSimulatedAttestationReport,
  verifyAttestationReport,
} from '../simulator/attestation.js';
import { ATTACK_SCENARIOS, runAttackSimulation } from '../simulator/attackScenarios.js';
import {
  getDockerStatus,
  startDeviceContainer,
  stopDeviceContainer,
  restartDeviceContainer,
} from '../services/dockerService.js';
import {
  PROTECTED_ASSETS,
  ATTACKER_PROFILES,
  TRUST_BOUNDARIES,
  RISK_SCORING_METHODOLOGY,
  THREAT_REGISTER,
  SECURITY_LIMITATIONS,
  runThreatSimulation,
  exportThreatRegisterCsv,
  generateThreatModelReportHtml,
} from '../../src/threatModel.js';
import {
  runFleetScalingBenchmark,
  abortBenchmark,
  exportBenchmarkHistoryCsv,
  getEnvironmentInfo,
} from '../../src/performance.js';
import {
  getBenchmarkHistory,
  deleteBenchmarkRun,
  getThreatTestHistory,
} from '../../src/database.js';

const router = express.Router();

// Multer storage in non-public /uploads directory
const uploadDir = path.resolve(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    // Generate safe randomized server-side filename (prevents path traversal / overwriting)
    const ext = path.extname(file.originalname).substring(0, 10);
    const safeName = `pkg_${Date.now()}_${crypto.randomBytes(8).toString('hex')}${ext}`;
    cb(null, safeName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit
  fileFilter: (_req, file, cb) => {
    // Basic file filter
    cb(null, true);
  },
});

/* ==========================================================================
   HEALTH & DASHBOARD
   ========================================================================== */

router.get('/health', (_req: Request, res: Response) => {
  res.json({
    ok: true,
    service: 'IoT CyberShield Core Engine',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    environment: 'Node.js 22 + SQLite + WebAssembly + Ed25519',
    mode: 'Software-Emulated IoT Security Lab',
  });
});

router.get('/dashboard', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();

    const totalDevices = queryScalar<number>(db, 'SELECT COUNT(*) FROM devices') || 0;
    const runningDevices = queryScalar<number>(db, "SELECT COUNT(*) FROM devices WHERE device_status = 'RUNNING' OR device_status = 'HEALTHY'") || 0;
    const healthyDevices = queryScalar<number>(db, "SELECT COUNT(*) FROM devices WHERE device_status = 'HEALTHY' OR device_status = 'RUNNING'") || 0;
    const stoppedDevices = queryScalar<number>(db, "SELECT COUNT(*) FROM devices WHERE device_status = 'STOPPED'") || 0;
    const disconnectedDevices = queryScalar<number>(db, "SELECT COUNT(*) FROM devices WHERE device_status = 'DEGRADED' OR security_status = 'COMPROMISED'") || 0;
    const attentionDevices = queryScalar<number>(db, "SELECT COUNT(*) FROM devices WHERE device_status = 'DEGRADED' OR security_status = 'WARNING' OR security_status = 'COMPROMISED'") || 0;

    const totalTests = queryScalar<number>(db, 'SELECT COUNT(*) FROM firmware_updates') || 0;
    const approvedUpdates = queryScalar<number>(db, "SELECT COUNT(*) FROM firmware_updates WHERE decision = 'APPROVED'") || 0;
    const rejectedUpdates = queryScalar<number>(db, "SELECT COUNT(*) FROM firmware_updates WHERE decision = 'REJECTED'") || 0;
    const totalSimulations = queryScalar<number>(db, 'SELECT COUNT(*) FROM simulation_sessions') || 0;

    const recentEvents = query(db, 'SELECT * FROM security_events ORDER BY created_at DESC LIMIT 6');
    const recentSimulations = query(db, 'SELECT * FROM simulation_sessions ORDER BY created_at DESC LIMIT 4');
    const devices = query(db, 'SELECT id, name, type, firmware_version, minimum_version, device_status, security_status FROM devices');

    const unacknowledgedAnomalies = queryScalar<number>(db, 'SELECT COUNT(*) FROM anomaly_alerts WHERE acknowledged = 0') || 0;

    // Real Docker status
    const dockerStatus = await getDockerStatus();

    // Real Process Memory & CPU
    const memUsage = process.memoryUsage();
    const memoryRssMb = Math.round((memUsage.rss / (1024 * 1024)) * 100) / 100;
    const memoryHeapMb = Math.round((memUsage.heapUsed / (1024 * 1024)) * 100) / 100;

    res.json({
      metrics: {
        totalDevices,
        onlineDevices: runningDevices,
        healthyDevices,
        stoppedDevices,
        disconnectedDevices,
        attentionDevices,
        runningDockerContainers: dockerStatus.runningContainers,
        firmwareTests: totalTests,
        approvedUpdates,
        rejectedUpdates,
        totalSimulations,
        unacknowledgedAnomalies,
        memoryRssMb,
        memoryHeapMb,
      },
      dockerStatus,
      devices,
      recentEvents,
      recentSimulations,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   VIRTUAL DEVICES
   ========================================================================== */

router.get('/devices', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const rows = query<any>(db, 'SELECT * FROM devices ORDER BY created_at ASC');
    const devicesWithTelemetry = rows.map(d => ({
      ...d,
      telemetry: getSimulatedTelemetry(d),
      config: JSON.parse(d.config_json || '{}'),
    }));
    res.json(devicesWithTelemetry);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/devices', async (req: Request, res: Response) => {
  try {
    const { id, name, type, firmwareVersion, minimumVersion, config } = req.body;
    if (!id || !name || !type || !firmwareVersion || !minimumVersion) {
      return res.status(400).json({ error: 'Device ID, Name, Type, Firmware Version, and Minimum Version are required.' });
    }

    const cleanId = String(id).trim().toUpperCase();
    if (!/^[A-Z0-9\-_]{3,24}$/.test(cleanId)) {
      return res.status(400).json({ error: 'Device ID must be 3-24 characters containing only alphanumeric letters, dashes, or underscores.' });
    }

    const db = await getDatabase();
    const existing = queryOne(db, 'SELECT id FROM devices WHERE id = ?', [cleanId]);
    if (existing) {
      return res.status(409).json({ error: `A virtual device with ID '${cleanId}' already exists. Device IDs must be unique.` });
    }

    const now = new Date().toISOString();
    const bootHash = calculateSha256(`CYBERSHIELD-ROM-${cleanId}-${firmwareVersion}`);
    const configStr = JSON.stringify(config || {});

    execute(
      db,
      `INSERT INTO devices (id, name, type, firmware_version, minimum_version, device_status, security_status, boot_hash, config_json, created_at)
       VALUES (?, ?, ?, ?, ?, 'STOPPED', 'SECURE', ?, ?, ?)`,
      [cleanId, name.trim(), type, firmwareVersion.trim(), minimumVersion.trim(), bootHash, configStr, now]
    );

    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, 'DEVICE_REGISTERED', 'INFO', ?, 'DEV_PROVISIONED', ?)`,
      [`EVT-REG-${Date.now()}`, cleanId, `Virtual device '${name}' (${cleanId}) registered in system.`, now]
    );

    const created = queryOne(db, 'SELECT * FROM devices WHERE id = ?', [cleanId]);
    res.status(201).json(created);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/devices/:id', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const device = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [req.params.id]);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    const recentUpdates = query(db, 'SELECT * FROM firmware_updates WHERE device_id = ? ORDER BY created_at DESC LIMIT 5', [req.params.id]);
    const recentEvents = query(db, 'SELECT * FROM security_events WHERE device_id = ? ORDER BY created_at DESC LIMIT 10', [req.params.id]);

    res.json({
      ...device,
      config: JSON.parse(device.config_json || '{}'),
      telemetry: getSimulatedTelemetry(device),
      recentUpdates,
      recentEvents,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.patch('/devices/:id', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const device = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [req.params.id]);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    const { name, config, minimumVersion } = req.body;
    if (name) {
      execute(db, 'UPDATE devices SET name = ? WHERE id = ?', [name.trim(), req.params.id]);
    }
    if (minimumVersion) {
      execute(db, 'UPDATE devices SET minimum_version = ? WHERE id = ?', [minimumVersion.trim(), req.params.id]);
    }
    if (config) {
      execute(db, 'UPDATE devices SET config_json = ? WHERE id = ?', [JSON.stringify(config), req.params.id]);
    }

    const updated = queryOne(db, 'SELECT * FROM devices WHERE id = ?', [req.params.id]);
    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/devices/:id', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const device = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [req.params.id]);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    execute(db, 'DELETE FROM devices WHERE id = ?', [req.params.id]);
    execute(db, 'DELETE FROM accepted_update_ids WHERE device_id = ?', [req.params.id]);

    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, 'DEVICE_DELETED', 'INFO', ?, 'DEV_REMOVED', ?)`,
      [`EVT-DEL-${Date.now()}`, req.params.id, `Virtual device '${device.name}' removed from registry.`, new Date().toISOString()]
    );

    res.json({ ok: true, message: `Device ${req.params.id} deleted successfully.` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/devices/:id/start', async (req: Request, res: Response) => {
  try {
    const result = await simulateSecureBoot(req.params.id);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/devices/:id/stop', async (req: Request, res: Response) => {
  try {
    await stopDevice(req.params.id);
    // Also stop Docker container if running
    try { await stopDeviceContainer(req.params.id); } catch { /* ignore if offline */ }
    res.json({ ok: true, status: 'STOPPED' });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/devices/:id/restart', async (req: Request, res: Response) => {
  try {
    await stopDevice(req.params.id);
    const bootResult = await simulateSecureBoot(req.params.id);
    // Also restart Docker container if Docker is active
    try { await restartDeviceContainer(req.params.id); } catch { /* ignore if offline */ }
    res.json({ ok: true, status: 'RESTARTED', bootResult });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/devices/:id/telemetry/randomize', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const device = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [req.params.id]);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    const telemetry = getSimulatedTelemetry(device);
    res.json(telemetry);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   DOCKER ENGINE INTEGRATION
   ========================================================================== */

router.get('/docker/status', async (_req: Request, res: Response) => {
  try {
    const status = await getDockerStatus();
    res.json(status);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/docker/devices/:id/start', async (req: Request, res: Response) => {
  try {
    const result = await startDeviceContainer(req.params.id);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/docker/devices/:id/stop', async (req: Request, res: Response) => {
  try {
    const result = await stopDeviceContainer(req.params.id);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/docker/devices/:id/restart', async (req: Request, res: Response) => {
  try {
    const result = await restartDeviceContainer(req.params.id);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

/* ==========================================================================
   FIRMWARE LAB & UPLOAD
   ========================================================================== */

router.post('/firmware/upload', upload.single('firmwareFile'), async (req: Request, res: Response) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No firmware file uploaded.' });
    }

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);
    const fileHash = calculateSha256(fileBuffer);
    const originalName = req.file.originalname;
    const ext = path.extname(originalName).toLowerCase();

    // Plain text safe test file detection
    if (ext === '.txt' || ext === '.log') {
      const textPreview = fileBuffer.toString('utf-8').substring(0, 300);
      return res.json({
        fileId: req.file.filename,
        fileName: originalName,
        fileSize: req.file.size,
        fileHash,
        detectedFormat: 'Plain Text Test Sample',
        isDeployableFirmware: false,
        warning: 'This is recognized as a harmless plain-text test sample, NOT deployable binary firmware. Firmware must be an authentic signed ZIP package containing manifest.json, firmware.bin, and firmware.sig.',
        preview: textPreview,
      });
    }

    // Try inspecting as ZIP package
    let manifestInfo: any = null;
    let isZip = false;
    let isDeployable = false;

    try {
      const JSZip = (await import('jszip')).default;
      const zip = await JSZip.loadAsync(fileBuffer);
      isZip = true;
      const manifestFile = zip.file('manifest.json');
      if (manifestFile) {
        const text = await manifestFile.async('text');
        manifestInfo = JSON.parse(text);
        isDeployable = true;
      }
    } catch {
      // not a zip
    }

    res.json({
      fileId: req.file.filename,
      fileName: originalName,
      fileSize: req.file.size,
      fileHash,
      detectedFormat: isZip ? (isDeployable ? 'IoT CyberShield Signed OTA Package (.zip)' : 'Generic ZIP Archive') : 'Raw Binary (.bin)',
      isDeployableFirmware: isDeployable,
      manifest: manifestInfo,
      targetDeviceType: manifestInfo?.deviceType || null,
      proposedVersion: manifestInfo?.firmwareVersion || null,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/firmware/verify', async (req: Request, res: Response) => {
  try {
    const { deviceId, fileId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'Target device ID is required.' });
    if (!fileId) return res.status(400).json({ error: 'File ID is required. Upload a file first.' });

    // Sanitize fileId to prevent path traversal
    const safeFileId = path.basename(fileId);
    const targetPath = path.join(uploadDir, safeFileId);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ error: 'Uploaded file not found or expired.' });
    }

    const fileBuffer = fs.readFileSync(targetPath);
    const result = await validateAndVerifyFirmware(fileBuffer, deviceId, safeFileId);

    const db = await getDatabase();
    const updateRecordId = `REC-${Date.now()}`;
    const now = new Date().toISOString();

    // Record firmware update evaluation in database
    execute(
      db,
      `INSERT INTO firmware_updates (id, device_id, package_id, update_id, previous_version, target_version, decision, reason, checks_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        updateRecordId,
        deviceId,
        safeFileId,
        result.updateId || 'N/A',
        result.previousVersion,
        result.proposedVersion,
        result.decision,
        result.reason,
        JSON.stringify(result.checks),
        now,
      ]
    );

    // If approved, flash to device simulator; if rejected, handle rejected state
    if (result.decision === 'APPROVED') {
      await applyApprovedFirmwareUpdate(
        deviceId,
        result.proposedVersion,
        result.calculatedHash || 'N/A',
        result.updateId
      );
    } else {
      await handleRejectedFirmwareUpdate(
        deviceId,
        result.reason,
        result.updateId || 'N/A',
        result.checks.find(c => c.status === 'FAILED')?.name || 'General Policy'
      );
    }

    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   SAMPLE PACKAGE GENERATOR
   ========================================================================== */

router.post('/firmware/generate-sample', async (req: Request, res: Response) => {
  try {
    const { deviceId, scenario } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'Target device ID is required.' });

    const packageResult = await generateFirmwarePackage({
      deviceId,
      scenario: scenario || 'valid',
    });

    // Save generated package to uploads folder so it can be verified directly!
    const safeName = `pkg_generated_${Date.now()}_${packageResult.fileName}`;
    const savePath = path.join(uploadDir, safeName);
    fs.writeFileSync(savePath, packageResult.buffer);

    res.json({
      fileId: safeName,
      fileName: packageResult.fileName,
      fileSize: packageResult.buffer.length,
      fileHash: calculateSha256(packageResult.buffer),
      scenario: packageResult.scenario,
      description: packageResult.description,
      expectedResult: packageResult.expectedResult,
      manifest: packageResult.manifest,
      readyToVerify: true,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/firmware/download-sample', async (req: Request, res: Response) => {
  try {
    const { fileId } = req.query;
    if (!fileId) return res.status(400).json({ error: 'fileId query parameter is required.' });

    const safeFileId = path.basename(String(fileId));
    const targetPath = path.join(uploadDir, safeFileId);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ error: 'Requested sample package file not found.' });
    }

    res.download(targetPath, safeFileId);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   ATTACK SIMULATION LAB
   ========================================================================== */

router.get('/simulations/scenarios', (_req: Request, res: Response) => {
  res.json(ATTACK_SCENARIOS);
});

router.post('/simulations', async (req: Request, res: Response) => {
  try {
    const { deviceId, scenarioType } = req.body;
    if (!deviceId || !scenarioType) {
      return res.status(400).json({ error: 'Device ID and Scenario Type are required.' });
    }

    const result = await runAttackSimulation(deviceId, scenarioType);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/simulations/history', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const rows = query(db, 'SELECT * FROM simulation_sessions ORDER BY created_at DESC LIMIT 20');
    res.json(rows.map(r => ({ ...r, steps: JSON.parse(r.steps_json || '[]') })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   REMOTE ATTESTATION
   ========================================================================== */

router.post('/devices/:id/attestation/challenge', async (req: Request, res: Response) => {
  try {
    const challenge = await createAttestationChallenge(req.params.id);
    res.json(challenge);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/devices/:id/attestation/simulate', async (req: Request, res: Response) => {
  try {
    const { challengeId, tamper } = req.body;
    if (!challengeId) return res.status(400).json({ error: 'Challenge ID is required.' });

    const report = await generateSimulatedAttestationReport(req.params.id, challengeId, Boolean(tamper));
    res.json(report);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/devices/:id/attestation/verify', async (req: Request, res: Response) => {
  try {
    const { challengeId, report } = req.body;
    if (!challengeId || !report) {
      return res.status(400).json({ error: 'challengeId and report payload are required.' });
    }

    const outcome = await verifyAttestationReport(req.params.id, challengeId, report);
    res.json(outcome);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

/* ==========================================================================
   SECURITY LOGS & AUDIT TRAIL
   ========================================================================== */

router.get('/logs', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const { deviceId, severity, eventType, search, limit = '50', offset = '0' } = req.query;

    let sql = 'SELECT * FROM security_events WHERE 1=1';
    const params: any[] = [];

    if (deviceId) {
      sql += ' AND device_id = ?';
      params.push(deviceId);
    }
    if (severity) {
      sql += ' AND severity = ?';
      params.push(severity);
    }
    if (eventType) {
      sql += ' AND event_type = ?';
      params.push(eventType);
    }
    if (search) {
      sql += ' AND (description LIKE ? OR reason_code LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as cnt');
    const totalCount = queryScalar<number>(db, countSql, params) || 0;

    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(String(limit), 10) || 50, parseInt(String(offset), 10) || 0);

    const rows = query(db, sql, params);

    res.json({
      total: totalCount,
      limit: parseInt(String(limit), 10),
      offset: parseInt(String(offset), 10),
      events: rows,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/logs/export-csv', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const rows = query<any>(db, 'SELECT id, created_at, device_id, event_type, severity, verification_result, reason_code, description FROM security_events ORDER BY created_at DESC');

    const headers = ['Event ID', 'Timestamp', 'Device ID', 'Event Type', 'Severity', 'Result', 'Reason Code', 'Description'];
    const csvLines = [headers.join(',')];

    for (const r of rows) {
      const line = [
        `"${r.id}"`,
        `"${r.created_at}"`,
        `"${r.device_id || ''}"`,
        `"${r.event_type}"`,
        `"${r.severity}"`,
        `"${r.verification_result || ''}"`,
        `"${r.reason_code}"`,
        `"${(r.description || '').replace(/"/g, '""')}"`,
      ].join(',');
      csvLines.push(line);
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_security_events.csv"');
    res.send(csvLines.join('\n'));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   PERFORMANCE TESTING BENCHMARKS
   ========================================================================== */

router.get('/performance/results', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const rows = query(db, 'SELECT * FROM performance_results ORDER BY created_at DESC LIMIT 15');
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/performance/run', async (req: Request, res: Response) => {
  try {
    const { iterations = 25, payloadSizeKb = 256 } = req.body;
    const iters = Math.min(100, Math.max(5, parseInt(String(iterations), 10) || 25));
    const testData = crypto.randomBytes(payloadSizeKb * 1024);

    const keyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const sampleSignature = crypto.sign(null, testData.subarray(0, 512), keyPair.privateKey);

    // Benchmark 1: SHA-256 Hashing
    const hashTimes: number[] = [];
    for (let i = 0; i < iters; i++) {
      const t0 = performance.now();
      calculateSha256(testData);
      hashTimes.push(performance.now() - t0);
    }

    // Benchmark 2: Ed25519 Signature Verification
    const sigTimes: number[] = [];
    const testSlice = testData.subarray(0, 512);
    for (let i = 0; i < iters; i++) {
      const t0 = performance.now();
      crypto.verify(null, testSlice, keyPair.publicKey, sampleSignature);
      sigTimes.push(performance.now() - t0);
    }

    // Benchmark 3: Canonical JSON Manifest Serialization
    const manifestObj = {
      packageFormatVersion: '1.0',
      deviceType: 'camera',
      firmwareVersion: '3.0.0',
      minimumSupportedVersion: '2.0.0',
      firmwareSha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      updateId: 'UPD-BENCH-TEST',
      keyId: 'dev-ed25519-primary',
      vendor: 'CyberShield-Secure-IoT',
    };
    const jsonTimes: number[] = [];
    for (let i = 0; i < iters; i++) {
      const t0 = performance.now();
      canonicalizeJson(manifestObj);
      jsonTimes.push(performance.now() - t0);
    }

    const calcStats = (times: number[]) => {
      const min = Math.min(...times);
      const max = Math.max(...times);
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      return {
        min: Number(min.toFixed(4)),
        max: Number(max.toFixed(4)),
        avg: Number(avg.toFixed(4)),
      };
    };

    const hashStats = calcStats(hashTimes);
    const sigStats = calcStats(sigTimes);
    const jsonStats = calcStats(jsonTimes);

    // Combined Pipeline estimation
    const pipelineAvg = Number((hashStats.avg + sigStats.avg + jsonStats.avg).toFixed(4));

    const db = await getDatabase();
    const now = new Date().toISOString();

    execute(
      db,
      `INSERT INTO performance_results (id, operation, iterations, avg_ms, min_ms, max_ms, success_count, failure_count, details_json, created_at)
       VALUES (?, 'SHA256_HASH', ?, ?, ?, ?, ?, 0, ?, ?),
              (?, 'ED25519_VERIFY', ?, ?, ?, ?, ?, 0, ?, ?),
              (?, 'CANONICAL_JSON', ?, ?, ?, ?, ?, 0, ?, ?)`,
      [
        `PERF-H-${Date.now()}`, iters, hashStats.avg, hashStats.min, hashStats.max, iters, JSON.stringify({ payloadSizeKb }), now,
        `PERF-S-${Date.now()}`, iters, sigStats.avg, sigStats.min, sigStats.max, iters, JSON.stringify({ algorithm: 'Ed25519' }), now,
        `PERF-J-${Date.now()}`, iters, jsonStats.avg, jsonStats.min, jsonStats.max, iters, JSON.stringify({ fields: 7 }), now,
      ]
    );

    res.json({
      iterations: iters,
      payloadSizeKb,
      benchmarks: {
        sha256: { name: 'SHA-256 Hashing', ...hashStats, unit: 'ms' },
        ed25519Verify: { name: 'Ed25519 Signature Verification', ...sigStats, unit: 'ms' },
        canonicalJson: { name: 'Canonical JSON Serialization', ...jsonStats, unit: 'ms' },
        fullPipelineEstimate: { name: 'Total Security Evaluation', avg: pipelineAvg, unit: 'ms' },
      },
      note: 'Measurements represent actual server host Node.js runtime crypto throughput.',
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================================================
   SETTINGS & ANOMALIES
   ========================================================================== */

router.get('/settings', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const settingsRows = query<{ key: string; value: string }>(db, 'SELECT key, value FROM application_settings');
    const settings: Record<string, string> = {};
    for (const r of settingsRows) settings[r.key] = r.value;

    const keys = query(db, 'SELECT key_id, name, public_key_hex, algorithm, is_active, is_revoked, created_at FROM trusted_signing_keys');

    res.json({ settings, trustedKeys: keys });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/settings', async (req: Request, res: Response) => {
  try {
    const { settings } = req.body;
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Settings object is required.' });
    }

    const db = await getDatabase();
    const now = new Date().toISOString();

    for (const [key, val] of Object.entries(settings)) {
      execute(
        db,
        `INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
        [key, String(val), now]
      );
    }

    res.json({ ok: true, message: 'Settings saved successfully.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/anomalies', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    const alerts = query(db, 'SELECT * FROM anomaly_alerts ORDER BY created_at DESC LIMIT 30');
    res.json(alerts);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/anomalies/:id/acknowledge', async (req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    execute(db, 'UPDATE anomaly_alerts SET acknowledged = 1 WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/reset-demo', async (_req: Request, res: Response) => {
  try {
    const db = await getDatabase();
    execute(db, 'DELETE FROM simulation_sessions');
    execute(db, 'DELETE FROM firmware_updates');
    execute(db, 'DELETE FROM accepted_update_ids');
    execute(db, 'DELETE FROM anomaly_alerts');
    execute(db, "DELETE FROM security_events WHERE event_type != 'SYSTEM_INITIALIZATION'");

/* ==========================================================================
   THREAT MODEL & SECURITY ANALYSIS
   ========================================================================== */

router.get('/threats', (_req: Request, res: Response) => {
  res.json({
    assets: PROTECTED_ASSETS,
    profiles: ATTACKER_PROFILES,
    boundaries: TRUST_BOUNDARIES,
    riskMethodology: RISK_SCORING_METHODOLOGY,
    threats: THREAT_REGISTER,
    limitations: SECURITY_LIMITATIONS,
  });
});

router.post('/threats/simulate', async (req: Request, res: Response) => {
  try {
    const { threatId, deviceId = 'DEV-CAM-01' } = req.body;
    const simulation = runThreatSimulation(threatId, deviceId);

    const db = await getDatabase();
    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, ?, ?, ?, 'THREAT_MODEL_SIMULATION', ?)`,
      [
        `EVT-THREAT-${Date.now()}`,
        deviceId,
        `THREAT_TEST_${simulation.threat.id}`,
        simulation.testResult.result === 'BLOCKED' ? 'HIGH' : 'INFO',
        `${simulation.testResult.blockedBy}: ${simulation.testResult.reason}`,
        new Date().toISOString(),
      ]
    );

    res.json(simulation);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/threats/tests-history', (_req: Request, res: Response) => {
  try {
    const history = getThreatTestHistory(50);
    res.json(history);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/threats/export-csv', (_req: Request, res: Response) => {
  try {
    const csv = exportThreatRegisterCsv();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_threat_register.csv"');
    res.send(csv);
  } catch (err: any) {
    res.status(500).send(`Error exporting CSV: ${err.message}`);
  }
});

router.get('/threats/report', (_req: Request, res: Response) => {
  const html = generateThreatModelReportHtml();
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

/* ==========================================================================
   HIGH-RESOLUTION BENCHMARKS & RESOURCE TIMERS
   ========================================================================== */

router.get('/benchmark/environment', (_req: Request, res: Response) => {
  res.json(getEnvironmentInfo());
});

router.post('/benchmark/run', async (req: Request, res: Response) => {
  try {
    const {
      fleetSize = 5,
      testRuns = 3,
      packageSizeBytes = 262144,
      simulateFailures = false,
    } = req.body || {};

    const result = await runFleetScalingBenchmark({
      fleetSize: Number(fleetSize),
      testRuns: Number(testRuns),
      packageSizeBytes: Number(packageSizeBytes),
      simulateFailures: Boolean(simulateFailures),
    });

    const db = await getDatabase();
    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, 'FLEET-BENCHMARK', 'PERFORMANCE_BENCHMARK', 'INFO', ?, 'BENCHMARK_COMPLETE', ?)`,
      [
        `EVT-BENCH-${Date.now()}`,
        `Completed benchmark for ${fleetSize} virtual devices (Overhead: ${result.overheadMs} ms, ${result.overheadPct !== null ? result.overheadPct + '%' : 'N/A'}).`,
        new Date().toISOString(),
      ]
    );

    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Benchmark failed.' });
  }
});

router.post('/benchmark/stop', (_req: Request, res: Response) => {
  const stopped = abortBenchmark();
  res.json({ stopped, message: stopped ? 'Benchmark stop signal received.' : 'No benchmark was running.' });
});

router.get('/benchmark/history', (_req: Request, res: Response) => {
  try {
    const history = getBenchmarkHistory(50);
    res.json(history);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/benchmark/history/:id', (req: Request, res: Response) => {
  try {
    deleteBenchmarkRun(req.params.id);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/benchmark/export-csv', (_req: Request, res: Response) => {
  try {
    const csv = exportBenchmarkHistoryCsv();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cybershield_benchmarks.csv"');
    res.send(csv);
  } catch (err: any) {
    res.status(500).send(`Error exporting CSV: ${err.message}`);
  }
});

export default router;
