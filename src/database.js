import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { initKeystore } from './cryptoUtils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, '..', 'data');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'cybershield.db');
let dbInstance = null;

export function getDatabase() {
  if (dbInstance) return dbInstance;

  dbInstance = new DatabaseSync(dbPath);

  // Initialize SQLite tables
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS benchmark_runs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      fleet_size INTEGER NOT NULL,
      test_runs INTEGER NOT NULL,
      package_size_bytes INTEGER NOT NULL,
      baseline_ms REAL NOT NULL,
      secure_ms REAL NOT NULL,
      overhead_ms REAL NOT NULL,
      overhead_pct REAL,
      hashing_ms REAL NOT NULL,
      signature_ms REAL NOT NULL,
      manifest_ms REAL NOT NULL,
      verification_ms REAL NOT NULL,
      update_processing_ms REAL NOT NULL,
      startup_shutdown_ms REAL NOT NULL,
      success_count INTEGER NOT NULL,
      fail_count INTEGER NOT NULL,
      avg_duration_ms REAL NOT NULL,
      min_duration_ms REAL NOT NULL,
      max_duration_ms REAL NOT NULL,
      cpu_user_ms REAL NOT NULL,
      cpu_system_ms REAL NOT NULL,
      memory_rss_mb REAL NOT NULL,
      memory_heap_mb REAL NOT NULL,
      environment_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threat_test_results (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      threat_id TEXT NOT NULL,
      threat_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      result TEXT NOT NULL,
      blocked_by TEXT NOT NULL,
      reason TEXT NOT NULL,
      defense_detail TEXT NOT NULL,
      residual_risk TEXT NOT NULL,
      raw_steps_json TEXT NOT NULL
    );

    -- EXACTLY FOUR SUPPORTED IoT DEVICES
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      model TEXT NOT NULL,
      category TEXT NOT NULL,
      type TEXT NOT NULL,
      image_url TEXT NOT NULL,
      firmware_version TEXT NOT NULL,
      minimum_version TEXT NOT NULL,
      policy_version TEXT NOT NULL,
      device_status TEXT NOT NULL DEFAULT 'Online',
      security_status TEXT NOT NULL DEFAULT 'SECURE',
      mode TEXT NOT NULL DEFAULT 'SIMULATED',
      last_seen_at TEXT NOT NULL,
      trusted_key_id TEXT NOT NULL DEFAULT 'dev-ed25519-primary',
      ip_address TEXT,
      container_health TEXT NOT NULL DEFAULT 'Docker unavailable',
      config_json TEXT NOT NULL DEFAULT '{}',
      telemetry_json TEXT NOT NULL DEFAULT '{}',
      risk_level TEXT NOT NULL DEFAULT 'Low',
      risk_explanation TEXT NOT NULL DEFAULT 'Normal baseline operation; all security policies enforced.',
      created_at TEXT NOT NULL
    );

    -- SECURITY EVENTS AUDIT TRAIL
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      originating_component TEXT NOT NULL,
      source_metadata TEXT,
      destination_metadata TEXT,
      request_id TEXT,
      package_id TEXT,
      detection_rule_id TEXT,
      evidence_json TEXT,
      related_incident_id TEXT,
      response_outcome TEXT NOT NULL,
      verification_result TEXT NOT NULL,
      description TEXT NOT NULL
    );

    -- COMPLETE INCIDENT INVESTIGATIONS (22 REQUIRED FORENSIC FIELDS)
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      classification TEXT NOT NULL,
      severity TEXT NOT NULL,
      severity_justification TEXT NOT NULL,
      device_id TEXT NOT NULL,
      device_model TEXT NOT NULL,
      timestamp_utc TEXT NOT NULL,
      timestamp_local TEXT NOT NULL,
      summary TEXT NOT NULL,
      attack_category TEXT NOT NULL,
      occurred_location TEXT NOT NULL,
      source_metadata TEXT NOT NULL,
      destination_metadata TEXT NOT NULL,
      entry_point TEXT NOT NULL,
      detection_rule_id TEXT NOT NULL,
      trigger_reason TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      correlated_events_json TEXT NOT NULL,
      observed_impact TEXT NOT NULL,
      response_action TEXT NOT NULL,
      response_success INTEGER NOT NULL DEFAULT 1,
      recovery_status TEXT NOT NULL,
      confidence_level TEXT NOT NULL,
      evidence_limitations TEXT NOT NULL,
      recommended_action TEXT NOT NULL,
      investigation_notes TEXT NOT NULL DEFAULT '',
      resolution_history_json TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'OPEN'
    );

    -- FIRMWARE VERIFICATIONS
    CREATE TABLE IF NOT EXISTS firmware_verifications (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      device_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      file_hash TEXT NOT NULL,
      trusted_hash TEXT,
      proposed_version TEXT NOT NULL,
      minimum_version TEXT NOT NULL,
      key_id TEXT,
      signature_status TEXT NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT NOT NULL,
      checks_json TEXT NOT NULL,
      request_id TEXT
    );

    -- TRUSTED SIGNING KEYS
    CREATE TABLE IF NOT EXISTS trusted_keys (
      key_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'Ed25519',
      public_key_hex TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TEXT NOT NULL
    );

    -- REPLAY PROTECTION CACHE
    CREATE TABLE IF NOT EXISTS accepted_replay_tokens (
      token_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      seen_at TEXT NOT NULL,
      PRIMARY KEY (device_id, token_id)
    );

    -- ANOMALY RULES
    CREATE TABLE IF NOT EXISTS anomaly_rules (
      rule_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      threshold REAL NOT NULL,
      unit TEXT NOT NULL,
      time_window_sec INTEGER NOT NULL,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      recommended_action TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1
    );

    -- ANOMALY ALERTS
    CREATE TABLE IF NOT EXISTS anomaly_alerts (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      evidence TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      analyst_note TEXT,
      acknowledged_at TEXT
    );

    -- SYSTEM AUDIT LOGS
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      actor TEXT NOT NULL DEFAULT 'Security Analyst',
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      details TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'SUCCESS'
    );

    -- APPLICATION SETTINGS
    CREATE TABLE IF NOT EXISTS application_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- 3D SIMULATION TRIALS (AUTOMATIC FIRMWARE UPDATE SERVER)
    CREATE TABLE IF NOT EXISTS simulation_trials_3d (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT NOT NULL,
      device_model TEXT NOT NULL,
      package_type TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      file_hash TEXT NOT NULL,
      expected_hash TEXT,
      firmware_version TEXT NOT NULL,
      key_id TEXT NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT NOT NULL,
      color TEXT NOT NULL,
      checks_json TEXT NOT NULL,
      incident_id TEXT,
      duration_ms REAL DEFAULT 0
    );
  `);

  seedInitialData(dbInstance);

  return dbInstance;
}

function seedInitialData(db) {
  const now = new Date().toISOString();

  // 1. Seed EXACTLY the four supported devices if empty
  const countRow = db.prepare('SELECT COUNT(*) as count FROM devices').get();
  if (!countRow || countRow.count === 0) {
    const devices = [
      {
        id: 'DEV-CAM-01',
        name: 'TP-Link Tapo C200',
        model: 'Tapo C200 (Pan/Tilt Wi-Fi Camera)',
        category: 'Smart Camera',
        type: 'camera',
        image_url: '/images/tapo-c200.png',
        firmware_version: '2.1.0',
        minimum_version: '2.0.0',
        policy_version: 'v2.0-STRICT',
        device_status: 'Online',
        security_status: 'SECURE',
        mode: 'SIMULATED',
        last_seen_at: now,
        trusted_key_id: 'dev-ed25519-primary',
        ip_address: '192.168.1.105',
        container_health: 'Docker unavailable',
        config_json: JSON.stringify({ rtspPort: 554, webPort: 80, fps: 30, privacyMode: false, storageUsedMb: 1420 }),
        telemetry_json: JSON.stringify({ activeStreams: 1, failedLogins: 0, bitrateKbps: 2048, cpuLoadPct: 18 }),
        risk_level: 'Low',
        risk_explanation: 'Normal baseline operation; all security policies enforced.',
        created_at: now
      },
      {
        id: 'DEV-LCK-02',
        name: 'ESP32 Smart Locker DevKit',
        model: 'DIY ESP32 DevKit + 4x4 Keypad + 12V Solenoid',
        category: 'Smart Access Control',
        type: 'smart_lock',
        image_url: '/images/smart-locker-esp32.png',
        firmware_version: '1.4.0',
        minimum_version: '1.3.0',
        policy_version: 'v1.4-ANTI-ROLLBACK',
        device_status: 'Online',
        security_status: 'SECURE',
        mode: 'SIMULATED',
        last_seen_at: now,
        trusted_key_id: 'dev-ed25519-primary',
        ip_address: '192.168.1.112',
        container_health: 'Docker unavailable',
        config_json: JSON.stringify({ autoRelockSec: 5, keypadActive: true, emergencyUnlockAllowed: false }),
        telemetry_json: JSON.stringify({ lockState: 'LOCKED', solenoidVolts: 12.0, failedPinAttempts: 0, lastUnlockTime: null }),
        risk_level: 'Low',
        risk_explanation: 'Physical solenoid secured; keypad access-control counters reset.',
        created_at: now
      },
      {
        id: 'DEV-ENV-03',
        name: 'DHT22 / AM2302 Environmental Sensor',
        model: 'DHT22 / AM2302 (Digital Capacitive Humidity & Temperature)',
        category: 'Environmental Sensor',
        type: 'environmental_sensor',
        image_url: '/images/dht22-am2302.png',
        firmware_version: '1.1.0',
        minimum_version: '1.0.0',
        policy_version: 'v1.0-INTEGRITY',
        device_status: 'Online',
        security_status: 'SECURE',
        mode: 'SIMULATED',
        last_seen_at: now,
        trusted_key_id: 'dev-ed25519-primary',
        ip_address: '192.168.1.120',
        container_health: 'Docker unavailable',
        config_json: JSON.stringify({ sampleRateSec: 5, tempMinCelsius: -10, tempMaxCelsius: 45, humMinPct: 15, humMaxPct: 85 }),
        telemetry_json: JSON.stringify({ temperatureCelsius: 22.4, humidityPercent: 48.2, readingStatus: 'NORMAL', lastReadingAt: now }),
        risk_level: 'Low',
        risk_explanation: 'Readings within expected thermal and humidity operating envelope.',
        created_at: now
      },
      {
        id: 'DEV-RTR-04',
        name: 'TP-Link Archer C6',
        model: 'Archer C6 (AC1200 MU-MIMO Gigabit Router)',
        category: 'Network Router',
        type: 'router',
        image_url: '/images/archer-c6.png',
        firmware_version: '1.2.0',
        minimum_version: '1.2.0',
        policy_version: 'v1.2-IMMUTABLE-BOOT',
        device_status: 'Online',
        security_status: 'SECURE',
        mode: 'SIMULATED',
        last_seen_at: now,
        trusted_key_id: 'dev-ed25519-primary',
        ip_address: '192.168.1.1',
        container_health: 'Docker unavailable',
        config_json: JSON.stringify({ adminPort: 443, firewallLevel: 'STRICT', natEnabled: true, dnsServer: '1.1.1.1' }),
        telemetry_json: JSON.stringify({ connectedClients: 14, wanStatus: 'CONNECTED', failedAdminLogins: 0, rxRateMbps: 45.2, txRateMbps: 12.8 }),
        risk_level: 'Low',
        risk_explanation: 'Stateful firewall active; administrative access restricted to local subnet.',
        created_at: now
      }
    ];

    const insertStmt = db.prepare(`
      INSERT INTO devices (
        id, name, model, category, type, image_url, firmware_version, minimum_version, policy_version,
        device_status, security_status, mode, last_seen_at, trusted_key_id, ip_address,
        container_health, config_json, telemetry_json, risk_level, risk_explanation, created_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?
      )
    `);

    for (const d of devices) {
      insertStmt.run(
        d.id, d.name, d.model, d.category, d.type, d.image_url, d.firmware_version, d.minimum_version, d.policy_version,
        d.device_status, d.security_status, d.mode, d.last_seen_at, d.trusted_key_id, d.ip_address,
        d.container_health, d.config_json, d.telemetry_json, d.risk_level, d.risk_explanation, d.created_at
      );
    }
  }

  // 2. Seed Trusted Keys
  const keyCount = db.prepare('SELECT COUNT(*) as count FROM trusted_keys').get();
  if (!keyCount || keyCount.count === 0) {
    const keystore = initKeystore();
    const insertKey = db.prepare(`
      INSERT INTO trusted_keys (key_id, name, algorithm, public_key_hex, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    if (keystore['dev-ed25519-primary']) {
      insertKey.run(
        'dev-ed25519-primary',
        keystore['dev-ed25519-primary'].name || 'Primary Hardware Root Signer (Dev)',
        'Ed25519',
        keystore['dev-ed25519-primary'].publicKeyHex,
        'ACTIVE',
        now
      );
    }
    if (keystore['dev-ed25519-secondary']) {
      insertKey.run(
        'dev-ed25519-secondary',
        keystore['dev-ed25519-secondary'].name || 'Secondary Field Update Signer (Dev)',
        'Ed25519',
        keystore['dev-ed25519-secondary'].publicKeyHex,
        'ACTIVE',
        now
      );
    }
  }

  // 3. Seed Anomaly Detection Rules
  const ruleCount = db.prepare('SELECT COUNT(*) as count FROM anomaly_rules').get();
  if (!ruleCount || ruleCount.count === 0) {
    const defaultRules = [
      {
        rule_id: 'RULE-AUTH-001',
        name: 'Repeated Authentication Failures',
        category: 'Authentication',
        threshold: 3,
        unit: 'failed attempts',
        time_window_sec: 60,
        severity: 'HIGH',
        description: 'Triggers when failed logins or keypad PIN attempts exceed threshold within window.',
        recommended_action: 'Enforce temporary simulated lockout and inspect source IP/interface logs.'
      },
      {
        rule_id: 'RULE-FREQ-002',
        name: 'Excessive Event Frequency',
        category: 'Behavioral Anomaly',
        threshold: 15,
        unit: 'events',
        time_window_sec: 10,
        severity: 'MEDIUM',
        description: 'Detects event floods or anomalous polling rates indicating denial-of-service attempts.',
        recommended_action: 'Apply rate limiting and quarantine affected device session.'
      },
      {
        rule_id: 'RULE-FW-003',
        name: 'Repeated Rejected Firmware Updates',
        category: 'Integrity Violation',
        threshold: 2,
        unit: 'rejections',
        time_window_sec: 120,
        severity: 'HIGH',
        description: 'Flags rapid successive attempts to push unsigned, tampered, or downgraded firmware.',
        recommended_action: 'Block OTA dispatching pipeline and initiate manual cryptographic audit.'
      },
      {
        rule_id: 'RULE-RPL-004',
        name: 'Replay Request Detection',
        category: 'Cryptographic Policy',
        threshold: 1,
        unit: 'duplicate nonce',
        time_window_sec: 3600,
        severity: 'HIGH',
        description: 'Detects reuse of previously processed transaction IDs, nonces, or package IDs.',
        recommended_action: 'Discard replayed package, verify anti-replay ledger, and alert security operations.'
      },
      {
        rule_id: 'RULE-RST-005',
        name: 'Unexpected Device Restart',
        category: 'Device Health & Availability',
        threshold: 2,
        unit: 'reboots',
        time_window_sec: 180,
        severity: 'MEDIUM',
        description: 'Monitors crash loops or unexpected restarts indicating memory faults or power anomalies.',
        recommended_action: 'Review crash dump logs. Note: Classify as health incident unless attack evidence is present.'
      },
      {
        rule_id: 'RULE-HBT-006',
        name: 'Missed Heartbeat Availability Failure',
        category: 'Availability',
        threshold: 30,
        unit: 'seconds without signal',
        time_window_sec: 30,
        severity: 'MEDIUM',
        description: 'Detects when an emulated node misses consecutive health heartbeats.',
        recommended_action: 'Verify emulator network container connectivity. Classify as health incident.'
      },
      {
        rule_id: 'RULE-ENV-007',
        name: 'Sensor Telemetry Limit Violation',
        category: 'Environmental Bounds',
        threshold: 45,
        unit: 'degrees Celsius',
        time_window_sec: 5,
        severity: 'MEDIUM',
        description: 'Triggers when DHT22 temperature or humidity exceeds safe configurable environmental envelope.',
        recommended_action: 'Verify physical environmental conditions and calibrate ADC baseline.'
      },
      {
        rule_id: 'RULE-CFG-008',
        name: 'Unapproved Configuration Change',
        category: 'Access Control',
        threshold: 1,
        unit: 'unauthorized change',
        time_window_sec: 60,
        severity: 'HIGH',
        description: 'Detects unauthorized modification of router DNS, firewall level, or camera privacy settings.',
        recommended_action: 'Revert device configuration to signed golden baseline and revoke active credentials.'
      },
      {
        rule_id: 'RULE-ACC-009',
        name: 'Camera Access Anomaly',
        category: 'Access Control',
        threshold: 5,
        unit: 'rapid requests',
        time_window_sec: 15,
        severity: 'HIGH',
        description: 'Detects unauthorized RTSP stream connection attempts or credential credential-stuffing.',
        recommended_action: 'Blacklist source address and cycle local camera streaming tokens.'
      },
      {
        rule_id: 'RULE-LCK-010',
        name: 'Locker Keypad Brute-Force / Tamper',
        category: 'Access Control',
        threshold: 3,
        unit: 'invalid PINs',
        time_window_sec: 60,
        severity: 'CRITICAL',
        description: 'Flags repeated invalid keypad entries on DIY ESP32 Solenoid Locker.',
        recommended_action: 'Trigger 5-minute simulated keypad lockout, sound physical alarm, and record incident.'
      }
    ];

    const insertRule = db.prepare(`
      INSERT INTO anomaly_rules (rule_id, name, category, threshold, unit, time_window_sec, severity, description, recommended_action, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const r of defaultRules) {
      insertRule.run(r.rule_id, r.name, r.category, r.threshold, r.unit, r.time_window_sec, r.severity, r.description, r.recommended_action, r.enabled ?? 1);
    }
  }

  // 4. Seed Default Settings
  const settingsCount = db.prepare('SELECT COUNT(*) as count FROM application_settings').get();
  if (!settingsCount || settingsCount.count === 0) {
    const insertSetting = db.prepare(`INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)`);
    insertSetting.run('max_upload_size_mb', '10', now);
    insertSetting.run('failed_login_lockout_threshold', '3', now);
    insertSetting.run('lockout_duration_seconds', '300', now);
    insertSetting.run('sensor_temp_alert_max', '45', now);
    insertSetting.run('sensor_temp_alert_min', '-10', now);
    insertSetting.run('sensor_hum_alert_max', '85', now);
    insertSetting.run('sensor_hum_alert_min', '15', now);
    insertSetting.run('heartbeat_timeout_seconds', '30', now);
    insertSetting.run('anomaly_detection_active', 'true', now);
  }

  // 5. Seed initial audit log
  const auditCount = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get();
  if (!auditCount || auditCount.count === 0) {
    const insertAudit = db.prepare(`
      INSERT INTO audit_logs (id, timestamp, actor, action, target, details, status)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    insertAudit.run(
      'AUD-INIT-001',
      now,
      'System Engine',
      'INITIALIZE_PLATFORM',
      'FLEET',
      'Initialized IoT CyberShield platform with exactly four supported reference devices.',
      'SUCCESS'
    );
  }
}

// -------------------------------------------------------------
// Benchmark Storage (Existing API Compatibility)
// -------------------------------------------------------------

export function saveBenchmarkRun(run) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO benchmark_runs (
      id, timestamp, fleet_size, test_runs, package_size_bytes,
      baseline_ms, secure_ms, overhead_ms, overhead_pct,
      hashing_ms, signature_ms, manifest_ms, verification_ms,
      update_processing_ms, startup_shutdown_ms,
      success_count, fail_count, avg_duration_ms, min_duration_ms, max_duration_ms,
      cpu_user_ms, cpu_system_ms, memory_rss_mb, memory_heap_mb, environment_json
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?
    )
  `);

  stmt.run(
    run.id,
    run.timestamp,
    run.fleetSize,
    run.testRuns,
    run.packageSizeBytes,
    run.baselineMs,
    run.secureMs,
    run.overheadMs,
    run.overheadPct !== null ? run.overheadPct : null,
    run.hashingMs,
    run.signatureMs,
    run.manifestMs,
    run.verificationMs,
    run.updateProcessingMs,
    run.startupShutdownMs,
    run.successCount,
    run.failCount,
    run.avgDurationMs,
    run.minDurationMs,
    run.maxDurationMs,
    run.cpuUserMs,
    run.cpuSystemMs,
    run.memoryRssMb,
    run.memoryHeapMb,
    JSON.stringify(run.environment)
  );
  return run;
}

export function getBenchmarkHistory(limit = 50) {
  const db = getDatabase();
  const stmt = db.prepare(`
    SELECT * FROM benchmark_runs ORDER BY timestamp DESC LIMIT ?
  `);
  const rows = stmt.all(limit);
  return rows.map(r => ({
    ...r,
    environment: JSON.parse(r.environment_json)
  }));
}

export function deleteBenchmarkRun(id) {
  const db = getDatabase();
  const stmt = db.prepare(`DELETE FROM benchmark_runs WHERE id = ?`);
  stmt.run(id);
}

export function saveThreatTestResult(testResult) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO threat_test_results (
      id, timestamp, threat_id, threat_name, device_id,
      result, blocked_by, reason, defense_detail, residual_risk, raw_steps_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    testResult.id,
    testResult.timestamp,
    testResult.threatId,
    testResult.threatName,
    testResult.deviceId,
    testResult.result,
    testResult.blockedBy,
    testResult.reason,
    testResult.defenseDetail,
    testResult.residualRisk,
    JSON.stringify(testResult.steps || [])
  );
  return testResult;
}

export function getThreatTestHistory(limit = 50) {
  const db = getDatabase();
  const stmt = db.prepare(`
    SELECT * FROM threat_test_results ORDER BY timestamp DESC LIMIT ?
  `);
  const rows = stmt.all(limit);
  return rows.map(r => ({
    ...r,
    steps: JSON.parse(r.raw_steps_json)
  }));
}

// -------------------------------------------------------------
// Devices Helpers
// -------------------------------------------------------------

export function getDevices() {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM devices ORDER BY id ASC').all();
  return rows.map(r => ({
    ...r,
    config: JSON.parse(r.config_json || '{}'),
    telemetry: JSON.parse(r.telemetry_json || '{}')
  }));
}

export function getDevice(id) {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
  if (!row) return null;
  return {
    ...row,
    config: JSON.parse(row.config_json || '{}'),
    telemetry: JSON.parse(row.telemetry_json || '{}')
  };
}

export function updateDevice(id, updates) {
  const db = getDatabase();
  const existing = getDevice(id);
  if (!existing) return null;

  const fields = [];
  const values = [];

  const validKeys = [
    'name', 'model', 'category', 'type', 'image_url', 'firmware_version', 'minimum_version',
    'policy_version', 'device_status', 'security_status', 'mode', 'last_seen_at',
    'trusted_key_id', 'ip_address', 'container_health', 'config_json', 'telemetry_json',
    'risk_level', 'risk_explanation'
  ];

  for (const [k, v] of Object.entries(updates)) {
    if (validKeys.includes(k)) {
      fields.push(`${k} = ?`);
      values.push(typeof v === 'object' ? JSON.stringify(v) : String(v));
    }
  }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE devices SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return getDevice(id);
}

// -------------------------------------------------------------
// Security Events Helpers
// -------------------------------------------------------------

export function addSecurityEvent(event) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO security_events (
      id, timestamp, device_id, event_type, severity, originating_component,
      source_metadata, destination_metadata, request_id, package_id,
      detection_rule_id, evidence_json, related_incident_id, response_outcome,
      verification_result, description
    ) VALUES (
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?
    )
  `);

  stmt.run(
    event.id,
    event.timestamp || new Date().toISOString(),
    event.deviceId,
    event.eventType,
    event.severity || 'INFO',
    event.originatingComponent || 'Unknown Component',
    event.sourceMetadata || 'Internal simulator',
    event.destinationMetadata || null,
    event.requestId || null,
    event.packageId || null,
    event.detectionRuleId || null,
    event.evidenceJson || (event.evidence ? JSON.stringify(event.evidence) : null),
    event.relatedIncidentId || null,
    event.responseOutcome || 'LOGGED',
    event.verificationResult || 'PASSED',
    event.description || ''
  );

  return event;
}

export function getSecurityEvents(filters = {}) {
  const db = getDatabase();
  let sql = 'SELECT * FROM security_events WHERE 1=1';
  const params = [];

  if (filters.deviceId && filters.deviceId !== 'ALL') {
    sql += ' AND device_id = ?';
    params.push(filters.deviceId);
  }
  if (filters.severity && filters.severity !== 'ALL') {
    sql += ' AND severity = ?';
    params.push(filters.severity);
  }
  if (filters.eventType && filters.eventType !== 'ALL') {
    sql += ' AND event_type = ?';
    params.push(filters.eventType);
  }
  if (filters.search) {
    sql += ' AND (description LIKE ? OR id LIKE ? OR reason_code LIKE ?)';
    const term = `%${filters.search}%`;
    params.push(term, term, term);
  }

  sql += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(filters.limit ? Number(filters.limit) : 200);

  const rows = db.prepare(sql).all(...params);
  return rows.map(r => ({
    ...r,
    evidence: r.evidence_json ? JSON.parse(r.evidence_json) : null
  }));
}

// -------------------------------------------------------------
// Incident Investigations Helpers (22 Required Fields)
// -------------------------------------------------------------

export function createIncident(incident) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO incidents (
      id, title, classification, severity, severity_justification,
      device_id, device_model, timestamp_utc, timestamp_local, summary,
      attack_category, occurred_location, source_metadata, destination_metadata,
      entry_point, detection_rule_id, trigger_reason, evidence_json,
      correlated_events_json, observed_impact, response_action, response_success,
      recovery_status, confidence_level, evidence_limitations, recommended_action,
      investigation_notes, resolution_history_json, status
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?
    )
  `);

  stmt.run(
    incident.id,
    incident.title,
    incident.classification,
    incident.severity,
    incident.severityJustification,
    incident.deviceId,
    incident.deviceModel,
    incident.timestampUtc,
    incident.timestampLocal,
    incident.summary,
    incident.attackCategory,
    incident.occurredLocation,
    incident.sourceMetadata,
    incident.destinationMetadata,
    incident.entryPoint,
    incident.detectionRuleId,
    incident.triggerReason,
    typeof incident.evidenceJson === 'object' ? JSON.stringify(incident.evidenceJson) : (incident.evidenceJson || '{}'),
    typeof incident.correlatedEventsJson === 'object' ? JSON.stringify(incident.correlatedEventsJson) : (incident.correlatedEventsJson || '[]'),
    incident.observedImpact,
    incident.responseAction,
    incident.responseSuccess ? 1 : 0,
    incident.recoveryStatus,
    incident.confidenceLevel,
    incident.evidenceLimitations,
    incident.recommendedAction,
    incident.investigationNotes || '',
    typeof incident.resolutionHistoryJson === 'object' ? JSON.stringify(incident.resolutionHistoryJson) : (incident.resolutionHistoryJson || '[]'),
    incident.status || 'OPEN'
  );

  return incident;
}

export function getIncidents(filters = {}) {
  const db = getDatabase();
  let sql = 'SELECT * FROM incidents WHERE 1=1';
  const params = [];

  if (filters.deviceId && filters.deviceId !== 'ALL') {
    sql += ' AND device_id = ?';
    params.push(filters.deviceId);
  }
  if (filters.severity && filters.severity !== 'ALL') {
    sql += ' AND severity = ?';
    params.push(filters.severity);
  }
  if (filters.status && filters.status !== 'ALL') {
    sql += ' AND status = ?';
    params.push(filters.status);
  }

  sql += ' ORDER BY timestamp_utc DESC LIMIT ?';
  params.push(filters.limit ? Number(filters.limit) : 100);

  const rows = db.prepare(sql).all(...params);
  return rows.map(r => ({
    ...r,
    evidence: JSON.parse(r.evidence_json || '{}'),
    correlatedEvents: JSON.parse(r.correlated_events_json || '[]'),
    resolutionHistory: JSON.parse(r.resolution_history_json || '[]')
  }));
}

export function getIncident(id) {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
  if (!row) return null;
  return {
    ...row,
    evidence: JSON.parse(row.evidence_json || '{}'),
    correlatedEvents: JSON.parse(row.correlated_events_json || '[]'),
    resolutionHistory: JSON.parse(row.resolution_history_json || '[]')
  };
}

export function updateIncident(id, updates) {
  const db = getDatabase();
  const existing = getIncident(id);
  if (!existing) return null;

  const notes = updates.investigationNotes !== undefined ? updates.investigationNotes : existing.investigation_notes;
  const status = updates.status !== undefined ? updates.status : existing.status;

  const history = existing.resolutionHistory || [];
  if (updates.status && updates.status !== existing.status) {
    history.push({
      timestamp: new Date().toISOString(),
      action: 'STATUS_CHANGED',
      from: existing.status,
      to: updates.status,
      note: updates.note || 'Status updated by analyst'
    });
  }
  if (updates.investigationNotes && updates.investigationNotes !== existing.investigation_notes) {
    history.push({
      timestamp: new Date().toISOString(),
      action: 'NOTE_ADDED',
      note: updates.investigationNotes
    });
  }

  db.prepare(`
    UPDATE incidents
    SET investigation_notes = ?, status = ?, resolution_history_json = ?
    WHERE id = ?
  `).run(notes, status, JSON.stringify(history), id);

  return getIncident(id);
}

// -------------------------------------------------------------
// Replay Protection Helpers
// -------------------------------------------------------------

export function checkAndRecordReplayToken(deviceId, tokenId) {
  if (!tokenId) return true; // Missing token counts as replay violation if required
  const db = getDatabase();
  const existing = db.prepare(`SELECT * FROM accepted_replay_tokens WHERE device_id = ? AND token_id = ?`).get(deviceId, tokenId);
  if (existing) {
    return false; // Replay detected!
  }
  db.prepare(`INSERT INTO accepted_replay_tokens (device_id, token_id, seen_at) VALUES (?, ?, ?)`).run(deviceId, tokenId, new Date().toISOString());
  return true;
}

// -------------------------------------------------------------
// Trusted Keys Helpers
// -------------------------------------------------------------

export function getTrustedKeys() {
  const db = getDatabase();
  return db.prepare('SELECT * FROM trusted_keys ORDER BY created_at DESC').all();
}

export function addTrustedKey(key) {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO trusted_keys (key_id, name, algorithm, public_key_hex, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(key.keyId, key.name, key.algorithm || 'Ed25519', key.publicKeyHex, key.status || 'ACTIVE', key.createdAt || new Date().toISOString());
  return key;
}

export function revokeTrustedKey(keyId) {
  const db = getDatabase();
  db.prepare(`UPDATE trusted_keys SET status = 'REVOKED' WHERE key_id = ?`).run(keyId);
  return getTrustedKeys();
}

// -------------------------------------------------------------
// Anomaly Rules & Alerts Helpers
// -------------------------------------------------------------

export function getAnomalyRules() {
  const db = getDatabase();
  return db.prepare('SELECT * FROM anomaly_rules ORDER BY rule_id ASC').all();
}

export function updateAnomalyRule(ruleId, updates) {
  const db = getDatabase();
  const fields = [];
  const values = [];
  if (updates.threshold !== undefined) {
    fields.push('threshold = ?');
    values.push(Number(updates.threshold));
  }
  if (updates.time_window_sec !== undefined) {
    fields.push('time_window_sec = ?');
    values.push(Number(updates.time_window_sec));
  }
  if (updates.enabled !== undefined) {
    fields.push('enabled = ?');
    values.push(updates.enabled ? 1 : 0);
  }
  if (fields.length > 0) {
    values.push(ruleId);
    db.prepare(`UPDATE anomaly_rules SET ${fields.join(', ')} WHERE rule_id = ?`).run(...values);
  }
  return db.prepare('SELECT * FROM anomaly_rules WHERE rule_id = ?').get(ruleId);
}

export function addAnomalyAlert(alert) {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO anomaly_alerts (id, timestamp, rule_id, device_id, severity, evidence, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    alert.id,
    alert.timestamp || new Date().toISOString(),
    alert.ruleId,
    alert.deviceId,
    alert.severity || 'MEDIUM',
    alert.evidence,
    alert.status || 'ACTIVE'
  );
  return alert;
}

export function getAnomalyAlerts(limit = 100) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM anomaly_alerts ORDER BY timestamp DESC LIMIT ?').all(limit);
}

export function resolveAnomalyAlert(id, status, analystNote) {
  const db = getDatabase();
  db.prepare(`
    UPDATE anomaly_alerts
    SET status = ?, analyst_note = ?, acknowledged_at = ?
    WHERE id = ?
  `).run(status, analystNote || '', new Date().toISOString(), id);
  return db.prepare('SELECT * FROM anomaly_alerts WHERE id = ?').get(id);
}

// -------------------------------------------------------------
// Audit Logs Helpers
// -------------------------------------------------------------

export function addAuditLog(entry) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO audit_logs (id, timestamp, actor, action, target, details, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    entry.id || `AUD-${Date.now()}`,
    entry.timestamp || new Date().toISOString(),
    entry.actor || 'Security Analyst',
    entry.action,
    entry.target,
    entry.details,
    entry.status || 'SUCCESS'
  );
  return entry;
}

export function getAuditLogs(limit = 100) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
}

// -------------------------------------------------------------
// Application Settings Helpers
// -------------------------------------------------------------

export function getSettings() {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM application_settings').all();
  const map = {};
  for (const r of rows) {
    map[r.key] = r.value;
  }
  return map;
}

export function updateSetting(key, value) {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO application_settings (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(key, String(value), new Date().toISOString());
  return getSettings();
}

// -------------------------------------------------------------
// 3D Simulation Trials Helpers (Automatic Firmware Server)
// -------------------------------------------------------------

export function addSimulationTrial(trial) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO simulation_trials_3d (
      id, timestamp, device_id, device_name, device_model, package_type,
      file_name, file_size, file_hash, expected_hash, firmware_version,
      key_id, decision, reason, color, checks_json, incident_id, duration_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    trial.id,
    trial.timestamp,
    trial.deviceId,
    trial.deviceName || trial.deviceId,
    trial.deviceModel || 'Virtual IoT Device',
    trial.packageType,
    trial.fileName,
    trial.fileSize || 0,
    trial.fileHash,
    trial.expectedHash || null,
    trial.firmwareVersion,
    trial.keyId || 'dev-ed25519-primary',
    trial.decision,
    trial.reason,
    trial.color || (trial.decision === 'APPROVED' ? 'green' : 'red'),
    JSON.stringify(trial.checks || []),
    trial.incidentId || null,
    trial.durationMs || 0
  );

  return trial;
}

export function getSimulationTrials(limit = 50) {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM simulation_trials_3d ORDER BY timestamp DESC LIMIT ?').all(limit);
  return rows.map(r => ({
    id: r.id,
    timestamp: r.timestamp,
    deviceId: r.device_id,
    deviceName: r.device_name,
    deviceModel: r.device_model,
    packageType: r.package_type,
    fileName: r.file_name,
    fileSize: r.file_size,
    fileHash: r.file_hash,
    expectedHash: r.expected_hash,
    firmwareVersion: r.firmware_version,
    keyId: r.key_id,
    decision: r.decision,
    reason: r.reason,
    color: r.color,
    checks: JSON.parse(r.checks_json || '[]'),
    incidentId: r.incident_id,
    durationMs: r.duration_ms
  }));
}

// -------------------------------------------------------------
// Demo Reset Helper
// -------------------------------------------------------------

export function resetDemoData() {
  const db = getDatabase();
  db.prepare('DELETE FROM security_events').run();
  db.prepare('DELETE FROM incidents').run();
  db.prepare('DELETE FROM anomaly_alerts').run();
  db.prepare('DELETE FROM accepted_replay_tokens').run();
  db.prepare('DELETE FROM firmware_verifications').run();
  db.prepare('DELETE FROM simulation_trials_3d').run();

  // Reset devices to clean state
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE devices
    SET device_status = 'Online', security_status = 'SECURE', risk_level = 'Low',
        risk_explanation = 'Normal baseline operation; all security policies enforced.',
        last_seen_at = ?
  `).run(now);

  addAuditLog({
    id: `AUD-RST-${Date.now()}`,
    timestamp: now,
    actor: 'Security Analyst',
    action: 'RESET_DEMO_STATE',
    target: 'PLATFORM',
    details: 'Reset transient telemetry, alert queues, 3D simulation trials, and test incident logs while preserving core keystore and device registry.',
    status: 'SUCCESS'
  });

  return { ok: true, message: 'Platform state reset successfully.' };
}

