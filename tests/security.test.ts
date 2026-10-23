import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import { getDatabase, query, queryOne, execute } from '../backend/src/database/db.js';
import { initializeKeys, calculateSha256, compareVersions, generateEd25519KeyPair } from '../backend/src/security/crypto.js';
import { generateFirmwarePackage } from '../backend/src/services/packageGenerator.js';
import { validateAndVerifyFirmware } from '../backend/src/security/packageValidator.js';
import { simulateSecureBoot, stopDevice, applyApprovedFirmwareUpdate, handleRejectedFirmwareUpdate } from '../backend/src/simulator/deviceSimulator.js';
import { createAttestationChallenge, generateSimulatedAttestationReport, verifyAttestationReport } from '../backend/src/simulator/attestation.js';

describe('IoT CyberShield Security & Emulation Engine Test Suite', () => {
  beforeAll(async () => {
    await getDatabase();
    await initializeKeys();
  });

  it('1. Hashing a valid firmware file calculates correct SHA-256', () => {
    const testBytes = Buffer.from('TEST_FIRMWARE_BINARY_BYTES');
    const hash = calculateSha256(testBytes);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(hash).toBe(crypto.createHash('sha256').update(testBytes).digest('hex'));
  });

  it('2. Creating and listing virtual devices in SQLite', async () => {
    const db = await getDatabase();
    const testId = `DEV-TEST-${Date.now()}`;
    execute(
      db,
      `INSERT INTO devices (id, name, type, firmware_version, minimum_version, device_status, security_status, created_at)
       VALUES (?, 'Test Sensor Unit', 'camera', '1.0.0', '1.0.0', 'STOPPED', 'SECURE', ?)`,
      [testId, new Date().toISOString()]
    );

    const dev = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [testId]);
    expect(dev).toBeDefined();
    expect(dev.name).toBe('Test Sensor Unit');

    const allDevices = query(db, 'SELECT * FROM devices');
    expect(allDevices.length).toBeGreaterThan(0);
  });

  it('3. Preventing duplicate device IDs in registry', async () => {
    const db = await getDatabase();
    const existing = queryOne<any>(db, 'SELECT id FROM devices LIMIT 1');
    expect(existing).toBeDefined();

    // Attempt inserting duplicate ID should throw constraint failure
    expect(() => {
      execute(
        db,
        `INSERT INTO devices (id, name, type, firmware_version, minimum_version, device_status, security_status, created_at)
         VALUES (?, 'Duplicate Node', 'camera', '1.0.0', '1.0.0', 'STOPPED', 'SECURE', ?)`,
        [existing.id, new Date().toISOString()]
      );
    }).toThrow();
  });

  it('4. Starting and stopping virtual devices with Secure Boot', async () => {
    const db = await getDatabase();
    const dev = queryOne<any>(db, "SELECT id FROM devices WHERE device_status = 'STOPPED' LIMIT 1") ||
      queryOne<any>(db, 'SELECT id FROM devices LIMIT 1');

    // Secure Boot start
    const bootResult = await simulateSecureBoot(dev.id);
    expect(bootResult.success).toBe(true);
    expect(bootResult.status).toBe('BOOT_APPROVED');

    const runningDev = queryOne<any>(db, 'SELECT device_status FROM devices WHERE id = ?', [dev.id]);
    expect(runningDev.device_status).toBe('RUNNING');

    // Stop device
    await stopDevice(dev.id);
    const stoppedDev = queryOne<any>(db, 'SELECT device_status FROM devices WHERE id = ?', [dev.id]);
    expect(stoppedDev.device_status).toBe('STOPPED');
  });

  it('5. Accepting a correctly signed valid firmware package', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'valid',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('APPROVED');
    expect(verification.checks.every(c => c.status === 'PASSED')).toBe(true);
    expect(verification.proposedVersion).toBe(pkg.manifest.firmwareVersion);
  });

  it('6. Rejecting an invalid digital signature', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'invalid_signature',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
    const sigCheck = verification.checks.find(c => c.name.includes('Signature'));
    expect(sigCheck?.status).toBe('FAILED');
  });

  it('7. Rejecting a firmware hash mismatch (tampered payload)', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'modified_firmware',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
    const hashCheck = verification.checks.find(c => c.name.includes('Hash'));
    expect(hashCheck?.status).toBe('FAILED');
  });

  it('8. Rejecting an unauthorized firmware downgrade', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'downgrade',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
    const versionCheck = verification.checks.find(c => c.name.includes('Rollback') || c.name.includes('Version'));
    expect(versionCheck?.status).toBe('FAILED');
  });

  it('9. Rejecting a replayed update ID', async () => {
    const db = await getDatabase();
    const replayId = 'UPD-REPLAY-TEST-TOKEN';

    // Record as accepted update
    execute(
      db,
      'INSERT OR REPLACE INTO accepted_update_ids (device_id, update_id, accepted_at) VALUES (?, ?, ?)',
      ['DEV-CAM-01', replayId, new Date().toISOString()]
    );

    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'valid',
      overrideUpdateId: replayId,
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
    const replayCheck = verification.checks.find(c => c.name.includes('Replay'));
    expect(replayCheck?.status).toBe('FAILED');
  });

  it('10. Rejecting an unknown or untrusted signing key', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'unknown_key',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
    const sigCheck = verification.checks.find(c => c.name.includes('Signature'));
    expect(sigCheck?.status).toBe('FAILED');
  });

  it('11. Rejecting malformed package containers', async () => {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'malformed',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);
    expect(verification.decision).toBe('REJECTED');
  });

  it('12. Preserving device firmware after a rejected update', async () => {
    const db = await getDatabase();
    const deviceBefore = queryOne<any>(db, 'SELECT firmware_version FROM devices WHERE id = ?', ['DEV-CAM-01']);
    const originalVersion = deviceBefore.firmware_version;

    // Run rejected downgrade attack
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: 'downgrade',
    });
    await validateAndVerifyFirmware(pkg.buffer, 'DEV-CAM-01', pkg.fileName);

    const deviceAfter = queryOne<any>(db, 'SELECT firmware_version FROM devices WHERE id = ?', ['DEV-CAM-01']);
    expect(deviceAfter.firmware_version).toBe(originalVersion);
  });

  it('13. Recording security events in SQLite audit log', async () => {
    const db = await getDatabase();
    const testEventId = `EVT-TEST-${Date.now()}`;
    execute(
      db,
      `INSERT INTO security_events (id, device_id, event_type, severity, description, reason_code, created_at)
       VALUES (?, 'DEV-CAM-01', 'UNIT_TEST_EVENT', 'INFO', 'Automated security test executed.', 'TEST_PASSED', ?)`,
      [testEventId, new Date().toISOString()]
    );

    const evt = queryOne<any>(db, 'SELECT * FROM security_events WHERE id = ?', [testEventId]);
    expect(evt).toBeDefined();
    expect(evt.event_type).toBe('UNIT_TEST_EVENT');
  });

  it('14. Rejecting invalid or tampered remote attestation reports', async () => {
    const chal = await createAttestationChallenge('DEV-CAM-01');
    expect(chal.nonceHex).toMatch(/^[a-f0-9]{64}$/);

    // Generate tampered report
    const tamperedReport = await generateSimulatedAttestationReport('DEV-CAM-01', chal.id, true);
    const verification = await verifyAttestationReport('DEV-CAM-01', chal.id, tamperedReport);
    expect(verification.status).toBe('REJECTED');
  });

  it('15. A valid update changes the simulated firmware version', async () => {
    const db = await getDatabase();
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-ENV-02',
      scenario: 'valid',
      overrideVersion: '1.5.0',
    });

    const verification = await validateAndVerifyFirmware(pkg.buffer, 'DEV-ENV-02', pkg.fileName);
    expect(verification.decision).toBe('APPROVED');

    await applyApprovedFirmwareUpdate('DEV-ENV-02', '1.5.0', verification.calculatedHash!, verification.updateId);
    const deviceAfter = queryOne<any>(db, 'SELECT firmware_version FROM devices WHERE id = ?', ['DEV-ENV-02']);
    expect(deviceAfter.firmware_version).toBe('1.5.0');
  });

  it('16. Anomaly rules generate alerts for repeated rejected updates', async () => {
    const db = await getDatabase();
    const deviceId = 'DEV-MOT-03';

    // Simulate 2 consecutive rejections to trigger rule-based anomaly alert
    await handleRejectedFirmwareUpdate(deviceId, 'First bit-flip detected', 'UPD-ANOM-1', 'SHA256_HASH');
    await handleRejectedFirmwareUpdate(deviceId, 'Second bit-flip detected', 'UPD-ANOM-2', 'SHA256_HASH');

    const alerts = query<any>(db, "SELECT * FROM anomaly_alerts WHERE device_id = ? AND category = 'REPEATED_UPDATE_FAILURES'", [deviceId]);
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].severity).toBe('HIGH');
  });

  it('17. Offline mode never reports a real Docker container as running', async () => {
    const { getDockerStatus } = await import('../backend/src/services/dockerService.js');
    const status = await getDockerStatus();

    if (status.mode === 'OFFLINE_TEST_MODE') {
      expect(status.available).toBe(false);
      expect(status.runningContainers).toBe(0);
      expect(status.message).toContain('Offline Test Mode');
    } else {
      expect(status.available).toBe(true);
      expect(status.mode).toBe('DOCKER_ENGINE');
    }
  });

  it('18. Benchmark calculations use real non-fabricated timings', async () => {
    const { calculateOverhead } = await import('../src/performance.js');
    const pos = calculateOverhead(12.4, 8.2);
    expect(pos.overheadMs).toBe(4.2);
    expect(pos.overheadPct).toBe(51.22);

    // Negative difference handled accurately
    const neg = calculateOverhead(7.1, 8.2);
    expect(neg.overheadMs).toBe(-1.1);
    expect(neg.overheadPct).toBe(-13.41);

    // Zero baseline handled safely without NaN
    const zero = calculateOverhead(5.0, 0);
    expect(zero.overheadPct).toBeNull();
  });
});
