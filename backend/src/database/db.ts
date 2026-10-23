import initSqlJs, { Database, SqlValue } from 'sql.js';
import fs from 'fs';
import path from 'path';

const DB_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DB_DIR, 'cybershield.db');

let dbInstance: Database | null = null;

// Ensure data and uploads directory exist
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}
const UPLOADS_DIR = path.resolve(process.cwd(), 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

export function saveDatabase(): void {
  if (!dbInstance) return;
  try {
    const data = dbInstance.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (err) {
    console.error('[Database] Failed to persist database to disk:', err);
  }
}

export async function getDatabase(): Promise<Database> {
  if (dbInstance) return dbInstance;

  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    try {
      const fileBuffer = fs.readFileSync(DB_PATH);
      dbInstance = new SQL.Database(fileBuffer);
    } catch (err) {
      console.warn('[Database] Corrupt database file, initializing fresh database:', err);
      dbInstance = new SQL.Database();
    }
  } else {
    dbInstance = new SQL.Database();
  }

  initSchema(dbInstance);
  saveDatabase();
  return dbInstance;
}

function initSchema(db: Database): void {
  db.run(`
    -- Virtual IoT Devices
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      firmware_version TEXT NOT NULL,
      minimum_version TEXT NOT NULL,
      device_status TEXT NOT NULL DEFAULT 'STOPPED', -- STOPPED, RUNNING, VERIFYING, UPDATING, HEALTHY, DEGRADED, UPDATE_REJECTED
      security_status TEXT NOT NULL DEFAULT 'SECURE', -- SECURE, WARNING, COMPROMISED
      last_boot_time TEXT,
      last_update_time TEXT,
      boot_hash TEXT,
      trusted_key_id TEXT NOT NULL DEFAULT 'dev-ed25519-primary',
      config_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );

    -- Firmware Packages uploaded / registered
    CREATE TABLE IF NOT EXISTS firmware_packages (
      id TEXT PRIMARY KEY,
      file_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      file_hash TEXT NOT NULL,
      package_format TEXT NOT NULL,
      device_type TEXT NOT NULL,
      target_version TEXT NOT NULL,
      minimum_version TEXT NOT NULL,
      key_id TEXT NOT NULL,
      is_valid_manifest INTEGER NOT NULL DEFAULT 0,
      uploaded_at TEXT NOT NULL,
      file_path TEXT
    );

    -- Firmware Update Attempts
    CREATE TABLE IF NOT EXISTS firmware_updates (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      package_id TEXT,
      update_id TEXT NOT NULL,
      previous_version TEXT NOT NULL,
      target_version TEXT NOT NULL,
      decision TEXT NOT NULL, -- APPROVED, REJECTED
      reason TEXT NOT NULL,
      checks_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (device_id) REFERENCES devices(id)
    );

    -- Persistent Accepted Update IDs for Replay Protection
    CREATE TABLE IF NOT EXISTS accepted_update_ids (
      device_id TEXT NOT NULL,
      update_id TEXT NOT NULL,
      accepted_at TEXT NOT NULL,
      PRIMARY KEY (device_id, update_id)
    );

    -- Trusted Signing Keys (Ed25519 public keys)
    CREATE TABLE IF NOT EXISTS trusted_signing_keys (
      key_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      public_key_hex TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'Ed25519',
      is_active INTEGER NOT NULL DEFAULT 1,
      is_revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    -- Simulation Sessions (Attack Lab & State Machine)
    CREATE TABLE IF NOT EXISTS simulation_sessions (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      scenario_type TEXT NOT NULL, -- invalid_signature, modified_firmware, downgrade, replay, unknown_key, malformed
      title TEXT NOT NULL,
      status TEXT NOT NULL, -- BLOCKED, PASSED, FAILED
      detected_check TEXT NOT NULL,
      affected_component TEXT NOT NULL,
      potential_impact TEXT NOT NULL,
      defense_action TEXT NOT NULL,
      steps_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    -- Security Event Logs (Persistent Audit Trail)
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL, -- INFO, LOW, MEDIUM, HIGH, CRITICAL
      description TEXT NOT NULL,
      update_id TEXT,
      verification_result TEXT,
      reason_code TEXT NOT NULL,
      metadata_json TEXT,
      created_at TEXT NOT NULL
    );

    -- Remote Attestation Challenges & Reports
    CREATE TABLE IF NOT EXISTS attestation_challenges (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      nonce_hex TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      is_used INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS attestation_reports (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      firmware_version TEXT NOT NULL,
      firmware_hash TEXT NOT NULL,
      status TEXT NOT NULL, -- VERIFIED, REJECTED
      reason TEXT NOT NULL,
      report_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    -- Performance Benchmark Results
    CREATE TABLE IF NOT EXISTS performance_results (
      id TEXT PRIMARY KEY,
      operation TEXT NOT NULL,
      iterations INTEGER NOT NULL,
      avg_ms REAL NOT NULL,
      min_ms REAL NOT NULL,
      max_ms REAL NOT NULL,
      success_count INTEGER NOT NULL,
      failure_count INTEGER NOT NULL,
      details_json TEXT,
      created_at TEXT NOT NULL
    );

    -- Application Settings
    CREATE TABLE IF NOT EXISTS application_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- Rule-based Anomaly Alerts
    CREATE TABLE IF NOT EXISTS anomaly_alerts (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      evidence TEXT NOT NULL,
      recommended_response TEXT NOT NULL,
      created_at TEXT NOT NULL,
      acknowledged INTEGER NOT NULL DEFAULT 0
    );
  `);

  // Seed default demonstration devices if table is empty
  const devCount = queryScalar<number>(db, 'SELECT COUNT(*) FROM devices');
  if (!devCount) {
    const now = new Date().toISOString();
    const defaultDevices = [
      {
        id: 'DEV-CAM-01',
        name: 'TP-Link Tapo C200',
        type: 'camera',
        firmware_version: '2.1.0',
        minimum_version: '2.0.0',
        device_status: 'RUNNING',
        security_status: 'SECURE',
        last_boot_time: now,
        boot_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        config_json: JSON.stringify({ model: 'Tapo C200', category: 'Smart Camera', rtspPort: 554, fps: 30, privacyMode: false }),
      },
      {
        id: 'DEV-LCK-02',
        name: 'ESP32 Smart Locker DevKit',
        type: 'smart_lock',
        firmware_version: '1.4.0',
        minimum_version: '1.3.0',
        device_status: 'RUNNING',
        security_status: 'SECURE',
        last_boot_time: now,
        boot_hash: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
        config_json: JSON.stringify({ model: 'DIY ESP32 DevKit + 4x4 Keypad + 12V Solenoid', category: 'Smart Access Control', autoLockSeconds: 5, keypadActive: true }),
      },
      {
        id: 'DEV-ENV-03',
        name: 'DHT22 / AM2302 Sensor',
        type: 'environmental_sensor',
        firmware_version: '1.1.0',
        minimum_version: '1.0.0',
        device_status: 'RUNNING',
        security_status: 'SECURE',
        last_boot_time: now,
        boot_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        config_json: JSON.stringify({ model: 'DHT22 / AM2302', category: 'Environmental Sensor', sampleRateSec: 5, alertThresholdCelsius: 45, humidityUpperPct: 80 }),
      },
      {
        id: 'DEV-RTR-04',
        name: 'TP-Link Archer C6',
        type: 'router',
        firmware_version: '1.2.0',
        minimum_version: '1.2.0',
        device_status: 'RUNNING',
        security_status: 'SECURE',
        last_boot_time: now,
        boot_hash: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4',
        config_json: JSON.stringify({ model: 'Archer C6 (AC1200 MU-MIMO)', category: 'Network Router', adminPort: 443, firewallLevel: 'STRICT', natEnabled: true }),
      },
    ];

    for (const d of defaultDevices) {
      db.run(
        `INSERT INTO devices (id, name, type, firmware_version, minimum_version, device_status, security_status, last_boot_time, boot_hash, config_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [d.id, d.name, d.type, d.firmware_version, d.minimum_version, d.device_status, d.security_status, d.last_boot_time, d.boot_hash, d.config_json, now]
      );
    }

    // Initial audit log
    db.run(
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ['EVT-INIT-001', 'SYSTEM', 'SYSTEM_INITIALIZATION', 'INFO', 'IoT CyberShield platform initialized with 4 software-emulated virtual nodes.', 'SYS_INIT_SUCCESS', now]
    );

    // Initial settings
    db.run(
      `INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?)`,
      [
        'max_upload_size_mb', '10', now,
        'allow_emergency_downgrade', 'false', now,
        'anomaly_detection_active', 'true', now,
      ]
    );
  }
}

export function query<T = Record<string, any>>(db: Database, sql: string, params: SqlValue[] = []): T[] {
  const stmt = db.prepare(sql);
  try {
    if (params && params.length > 0) {
      stmt.bind(params);
    }
    const results: T[] = [];
    while (stmt.step()) {
      results.push(stmt.getAsObject() as unknown as T);
    }
    return results;
  } finally {
    stmt.free();
  }
}

export function queryOne<T = Record<string, any>>(db: Database, sql: string, params: SqlValue[] = []): T | null {
  const list = query<T>(db, sql, params);
  return list.length > 0 ? list[0] : null;
}

export function queryScalar<T = any>(db: Database, sql: string, params: SqlValue[] = []): T | null {
  const row = queryOne<Record<string, any>>(db, sql, params);
  if (!row) return null;
  const firstKey = Object.keys(row)[0];
  return row[firstKey] as T;
}

export function execute(db: Database, sql: string, params: SqlValue[] = []): void {
  db.run(sql, params);
  saveDatabase();
}
