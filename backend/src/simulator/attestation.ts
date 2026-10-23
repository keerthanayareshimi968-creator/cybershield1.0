import crypto from 'crypto';
import { getDatabase, queryOne, execute } from '../database/db.js';
import { canonicalizeJson, verifyEd25519, signEd25519, getDevPrivateKey } from '../security/crypto.js';

export interface AttestationChallenge {
  id: string;
  deviceId: string;
  nonceHex: string;
  createdAt: string;
  expiresAt: string;
}

export interface AttestationReport {
  deviceId: string;
  firmwareVersion: string;
  firmwareHash: string;
  policyVersion: string;
  timestamp: string;
  challengeNonce: string;
  signatureHex: string;
  keyId: string;
  simulatedPcrValues?: Record<string, string>;
}

export async function createAttestationChallenge(deviceId: string): Promise<AttestationChallenge> {
  const db = await getDatabase();
  const challengeId = `CHAL-${crypto.randomUUID().substring(0, 8).toUpperCase()}`;
  const nonceHex = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();

  execute(
    db,
    `INSERT INTO attestation_challenges (id, device_id, nonce_hex, created_at, expires_at, is_used)
     VALUES (?, ?, ?, ?, ?, 0)`,
    [challengeId, deviceId, nonceHex, now.toISOString(), expiresAt]
  );

  return {
    id: challengeId,
    deviceId,
    nonceHex,
    createdAt: now.toISOString(),
    expiresAt,
  };
}

/**
 * Generate simulated attestation report signed by device development key
 */
export async function generateSimulatedAttestationReport(
  deviceId: string,
  challengeId: string,
  tamper: boolean = false
): Promise<AttestationReport> {
  const db = await getDatabase();
  const challenge = queryOne<{ id: string; device_id: string; nonce_hex: string; is_used: number; expires_at: string }>(
    db,
    'SELECT * FROM attestation_challenges WHERE id = ? AND device_id = ?',
    [challengeId, deviceId]
  );

  if (!challenge) {
    throw new Error('Attestation challenge not found.');
  }

  const device = queryOne<{ id: string; firmware_version: string; boot_hash: string; trusted_key_id: string }>(
    db,
    'SELECT id, firmware_version, boot_hash, trusted_key_id FROM devices WHERE id = ?',
    [deviceId]
  );

  if (!device) {
    throw new Error('Device not found.');
  }

  const keyId = device.trusted_key_id || 'dev-ed25519-primary';
  const privateKey = getDevPrivateKey(keyId);
  if (!privateKey) {
    throw new Error(`Device private signing key '${keyId}' not loaded.`);
  }

  const hash = tamper ? 'deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677' : device.boot_hash || '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8';

  const reportPayload = {
    deviceId: device.id,
    firmwareVersion: device.firmware_version,
    firmwareHash: hash,
    policyVersion: 'SEC-OTA-1.0',
    timestamp: new Date().toISOString(),
    challengeNonce: challenge.nonce_hex,
    simulatedPcrValues: {
      PCR0_BOOT_LOADER: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
      PCR1_KERNEL_ROM: hash.substring(0, 32),
      PCR2_CONFIG_STORE: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
    },
  };

  const canonical = canonicalizeJson(reportPayload);
  let signatureHex = signEd25519(canonical, privateKey);

  if (tamper) {
    signatureHex = signatureHex.substring(0, signatureHex.length - 8) + 'bad0cafe';
  }

  return {
    ...reportPayload,
    signatureHex,
    keyId,
  };
}

/**
 * Verify remote attestation report on the server
 */
export async function verifyAttestationReport(
  deviceId: string,
  challengeId: string,
  report: AttestationReport
): Promise<{
  status: 'VERIFIED' | 'REJECTED';
  reason: string;
  checks: Array<{ name: string; status: 'PASSED' | 'FAILED'; detail: string }>;
}> {
  const db = await getDatabase();
  const checks: Array<{ name: string; status: 'PASSED' | 'FAILED'; detail: string }> = [];

  // Check 1: Challenge validity & freshness
  const challenge = queryOne<{ id: string; nonce_hex: string; is_used: number; expires_at: string }>(
    db,
    'SELECT id, nonce_hex, is_used, expires_at FROM attestation_challenges WHERE id = ? AND device_id = ?',
    [challengeId, deviceId]
  );

  if (!challenge) {
    checks.push({
      name: 'Challenge Verification',
      status: 'FAILED',
      detail: `Challenge ID '${challengeId}' does not exist for device '${deviceId}'.`,
    });
  } else if (challenge.is_used === 1) {
    checks.push({
      name: 'Challenge Verification',
      status: 'FAILED',
      detail: `Challenge nonce '${challenge.nonce_hex.substring(0, 16)}...' has already been used. Replay attempt blocked.`,
    });
  } else if (new Date(challenge.expires_at).getTime() < Date.now()) {
    checks.push({
      name: 'Challenge Verification',
      status: 'FAILED',
      detail: 'Challenge has expired. Stale attestation report rejected.',
    });
  } else if (challenge.nonce_hex !== report.challengeNonce) {
    checks.push({
      name: 'Challenge Verification',
      status: 'FAILED',
      detail: 'Challenge nonce in report does not match the active server challenge.',
    });
  } else {
    checks.push({
      name: 'Challenge Verification',
      status: 'PASSED',
      detail: 'Fresh, single-use cryptographic challenge nonce verified.',
    });
  }

  // Check 2: Device State Matching
  const device = queryOne<{ id: string; firmware_version: string; boot_hash: string }>(
    db,
    'SELECT id, firmware_version, boot_hash FROM devices WHERE id = ?',
    [deviceId]
  );

  if (!device) {
    checks.push({
      name: 'Device State Measurement',
      status: 'FAILED',
      detail: 'Target device not found in active registry.',
    });
  } else if (device.firmware_version !== report.firmwareVersion) {
    checks.push({
      name: 'Device State Measurement',
      status: 'FAILED',
      detail: `Reported firmware v${report.firmwareVersion} does not match server registered v${device.firmware_version}.`,
    });
  } else if (device.boot_hash && device.boot_hash !== report.firmwareHash) {
    checks.push({
      name: 'Device State Measurement',
      status: 'FAILED',
      detail: 'Reported runtime firmware hash does not match trusted device baseline.',
    });
  } else {
    checks.push({
      name: 'Device State Measurement',
      status: 'PASSED',
      detail: `Firmware v${report.firmwareVersion} and image measurements match registered security baseline.`,
    });
  }

  // Check 3: Digital Signature Verification
  const canonical = canonicalizeJson({
    deviceId: report.deviceId,
    firmwareVersion: report.firmwareVersion,
    firmwareHash: report.firmwareHash,
    policyVersion: report.policyVersion,
    timestamp: report.timestamp,
    challengeNonce: report.challengeNonce,
    simulatedPcrValues: report.simulatedPcrValues,
  });

  const sigResult = await verifyEd25519(canonical, report.signatureHex, report.keyId);
  if (!sigResult.verified) {
    checks.push({
      name: 'Cryptographic Signature',
      status: 'FAILED',
      detail: sigResult.error || 'Attestation report signature invalid.',
    });
  } else {
    checks.push({
      name: 'Cryptographic Signature',
      status: 'PASSED',
      detail: `Report authenticated by key '${report.keyId}' (${sigResult.keyName}).`,
    });
  }

  const allPassed = checks.every(c => c.status === 'PASSED');
  const now = new Date().toISOString();

  // Mark challenge as used
  if (challenge) {
    execute(db, 'UPDATE attestation_challenges SET is_used = 1 WHERE id = ?', [challengeId]);
  }

  const status = allPassed ? 'VERIFIED' : 'REJECTED';
  const reason = allPassed
    ? 'Remote attestation report verified successfully against hardware security policy.'
    : checks.filter(c => c.status === 'FAILED').map(c => c.detail).join(' | ');

  execute(
    db,
    `INSERT INTO attestation_reports (id, device_id, challenge_id, firmware_version, firmware_hash, status, reason, report_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      `REP-${Date.now()}`,
      deviceId,
      challengeId,
      report.firmwareVersion,
      report.firmwareHash,
      status,
      reason,
      JSON.stringify(report),
      now,
    ]
  );

  execute(
    db,
    `INSERT INTO security_events (id, device_id, event_type, severity, description, verification_result, reason_code, created_at)
     VALUES (?, ?, 'REMOTE_ATTESTATION', ?, ?, ?, 'ATTESTATION_EVAL', ?)`,
    [
      `EVT-ATT-${Date.now()}`,
      deviceId,
      allPassed ? 'INFO' : 'HIGH',
      `Remote attestation ${status} for ${deviceId}: ${reason}`,
      status,
      now,
    ]
  );

  return {
    status,
    reason,
    checks,
  };
}
