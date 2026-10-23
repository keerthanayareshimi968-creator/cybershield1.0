import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  getDevice,
  updateDevice,
  getDevices,
  addSimulationTrial,
  getSimulationTrials
} from './database.js';

import {
  calculateSha256,
  signWithEd25519
} from './cryptoUtils.js';

import { evaluateFirmwarePackage } from './detectionEngine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const samplesDir = path.join(__dirname, '..', 'public', 'test-packages', 'auto-samples');

if (!fs.existsSync(samplesDir)) {
  fs.mkdirSync(samplesDir, { recursive: true });
}

// In-memory cache of latest generated packages per device
const cachedPackages = new Map();

/**
 * Generate two sample firmware files: one valid, one invalid
 */
export function generateSampleFirmwareFiles(deviceId = 'DEV-CAM-01') {
  const device = getDevice(deviceId) || getDevices()[0];
  if (!device) {
    throw new Error('Device not found');
  }

  // Calculate target version: increment patch
  const parts = device.firmware_version.split('.').map(n => parseInt(n, 10) || 0);
  const targetVersion = `${parts[0] || 2}.${(parts[1] || 0) + 1}.0`;
  const timestamp = new Date().toISOString();

  // -------------------------------------------------------------
  // 1. VALID FIRMWARE FILE
  // -------------------------------------------------------------
  const validHeader = `CYBERSHIELD-SECURE-OTA-CONTAINER-v2.0\n` +
    `DEVICE_TARGET=${device.id}\n` +
    `DEVICE_MODEL=${device.model}\n` +
    `VERSION=${targetVersion}\n` +
    `TIMESTAMP=${timestamp}\n` +
    `BUILD_PIPELINE=Automated-CI-Release-Secure\n` +
    `SIGNER_KEY_ID=dev-ed25519-primary\n` +
    `SECTION=.text\n`;

  const validPayloadBytes = crypto.randomBytes(512);
  const validBinary = Buffer.concat([Buffer.from(validHeader, 'utf-8'), validPayloadBytes]);
  const validHash = calculateSha256(validBinary);

  // Sign with the primary hardware root key
  let validSignatureHex = '';
  try {
    const sigBuf = signWithEd25519(validBinary, 'dev-ed25519-primary');
    validSignatureHex = sigBuf.toString('hex');
  } catch (err) {
    validSignatureHex = crypto.randomBytes(64).toString('hex');
  }

  const validFileName = `firmware_${device.id}_v${targetVersion}_VALID.bin`;
  const validFilePath = path.join(samplesDir, validFileName);
  fs.writeFileSync(validFilePath, validBinary);

  const validPackage = {
    id: `PKG-VAL-${Date.now().toString(36)}`,
    type: 'valid',
    fileName: validFileName,
    filePath: `/test-packages/auto-samples/${validFileName}`,
    fileSize: validBinary.length,
    fileHash: validHash,
    expectedHash: validHash,
    firmwareVersion: targetVersion,
    keyId: 'dev-ed25519-primary',
    signature: validSignatureHex,
    signatureValid: true,
    deviceId: device.id,
    generatedAt: timestamp,
    expectedOutcome: 'APPROVED',
    visualIndicator: 'green_carry_to_device',
    description: 'Authentic cryptographic package signed with Ed25519 Hardware Root Key. Valid SHA-256 digest and monotonic anti-rollback policy compliance (v' + targetVersion + ' > v' + device.minimum_version + ').'
  };

  // -------------------------------------------------------------
  // 2. INVALID FIRMWARE FILE (Adversarial / Tampered Attack)
  // -------------------------------------------------------------
  const invalidHeader = `MALICIOUS-MODIFIED-OTA-PAYLOAD-v2.0\n` +
    `DEVICE_TARGET=${device.id}\n` +
    `EXPLOIT_VECTOR=UNAUTHORIZED_CODE_INJECTION\n` +
    `VERSION=${targetVersion}\n` +
    `TIMESTAMP=${timestamp}\n` +
    `FORGED_SIGNER=dev-ed25519-primary\n`;

  const invalidPayloadBytes = Buffer.concat([
    Buffer.from('ATTACK_VECTOR_SHELLCODE_BUFFER_OVERFLOW_SIMULATION\x00\xDE\xAD\xBE\xEF', 'binary'),
    crypto.randomBytes(480)
  ]);
  const invalidBinary = Buffer.concat([Buffer.from(invalidHeader, 'utf-8'), invalidPayloadBytes]);
  const invalidHash = calculateSha256(invalidBinary);

  // Deliberately corrupted / forged digital signature
  const forgedSignatureHex = 'badc0de000000000000000000000000000000000000000000000000000000000' +
    'deadbeef00000000000000000000000000000000000000000000000000000000';

  const invalidFileName = `firmware_${device.id}_v${targetVersion}_INVALID_TAMPERED.bin`;
  const invalidFilePath = path.join(samplesDir, invalidFileName);
  fs.writeFileSync(invalidFilePath, invalidBinary);

  const invalidPackage = {
    id: `PKG-INV-${Date.now().toString(36)}`,
    type: 'invalid',
    fileName: invalidFileName,
    filePath: `/test-packages/auto-samples/${invalidFileName}`,
    fileSize: invalidBinary.length,
    fileHash: invalidHash,
    expectedHash: '0000000000000000000000000000000000000000000000000000000000000000', // Mismatch to trigger hash validation
    firmwareVersion: targetVersion,
    keyId: 'dev-ed25519-primary',
    signature: forgedSignatureHex,
    signatureValid: false,
    deviceId: device.id,
    generatedAt: timestamp,
    expectedOutcome: 'REJECTED',
    visualIndicator: 'red_blocked_before_device',
    description: 'Adversarial payload with tampered binary bytes and forged Ed25519 signature. Fails mandatory SHA-256 digest match and cryptographic authenticity checks.'
  };

  const bundle = {
    deviceId: device.id,
    device: {
      id: device.id,
      name: device.name,
      model: device.model,
      currentVersion: device.firmware_version,
      minVersion: device.minimum_version,
      imageUrl: device.image_url
    },
    targetVersion,
    generatedAt: timestamp,
    validPackage,
    invalidPackage
  };

  cachedPackages.set(device.id, bundle);
  return bundle;
}

/**
 * Execute a verification trial for either the valid or invalid sample firmware
 */
export async function runVerificationTrial(deviceId, packageType = 'valid', options = {}) {
  const device = getDevice(deviceId);
  if (!device) {
    throw new Error(`Device '${deviceId}' not found.`);
  }

  // Ensure packages exist
  let bundle = cachedPackages.get(device.id);
  if (!bundle) {
    bundle = generateSampleFirmwareFiles(device.id);
  }

  const pkg = packageType === 'valid' ? bundle.validPackage : bundle.invalidPackage;
  const requestId = `REQ-OTA-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const startTime = Date.now();
  const diskPath = path.join(samplesDir, pkg.fileName);
  let fileBuffer = null;
  if (fs.existsSync(diskPath)) {
    try {
      fileBuffer = fs.readFileSync(diskPath);
    } catch (err) {
      console.warn(`[OTA Server] Could not read file ${diskPath}:`, err.message);
    }
  }

  const payload = {
    fileName: pkg.fileName,
    firmwareBytes: fileBuffer,
    fileHash: fileBuffer ? calculateSha256(fileBuffer) : pkg.fileHash,
    expectedHash: packageType === 'valid' ? pkg.expectedHash : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    firmwareVersion: pkg.firmwareVersion,
    keyId: pkg.keyId,
    signature: pkg.signature,
    requestId,
    packageId: pkg.id
  };

  // Run through the existing security verification engine
  const evaluation = await evaluateFirmwarePackage(payload, device.id, {
    sourceIp: 'Auto-Update Server (10.0.8.25)',
    applyUpdate: packageType === 'valid' // Apply update on valid pass
  });

  const durationMs = Date.now() - startTime;
  const isApproved = evaluation.decision === 'APPROVED';

  if (isApproved) {
    // Invalidate cached bundle so next bundle generated targets the incremented version
    cachedPackages.delete(device.id);
  }

  // 3D Visual animation directives
  const animation = {
    color: isApproved ? 'green' : 'red',
    type: isApproved ? 'carry_to_device' : 'blocked_before_device',
    lineHex: isApproved ? '#10B981' : '#EF4444',
    particleHex: isApproved ? '#34D399' : '#F87171',
    barrierAction: isApproved ? 'PASS_THROUGH' : 'DEFLECT_AND_DESTROY',
    deviceReaction: isApproved ? 'ACCEPT_AND_FLASH' : 'SHIELD_PROTECTED_IDLE',
    sourceServerName: 'Automatic OTA Firmware Server',
    targetDeviceName: device.name
  };

  const trialId = `TRL-3D-${Date.now().toString(36).toUpperCase()}`;
  const now = new Date().toISOString();

  const trialRecord = {
    id: trialId,
    timestamp: now,
    deviceId: device.id,
    deviceName: device.name,
    deviceModel: device.model,
    packageType,
    fileName: pkg.fileName,
    fileSize: pkg.fileSize,
    fileHash: pkg.fileHash,
    expectedHash: payload.expectedHash,
    firmwareVersion: pkg.firmwareVersion,
    keyId: pkg.keyId,
    decision: evaluation.decision,
    reason: evaluation.reason,
    color: animation.color,
    checks: evaluation.checks,
    incidentId: evaluation.incidentId,
    durationMs
  };

  // Save to database
  addSimulationTrial(trialRecord);

  // Fetch updated device state (firmware may have incremented if approved)
  const updatedDevice = getDevice(device.id);

  return {
    trialId,
    timestamp: now,
    packageType,
    fileName: pkg.fileName,
    fileSize: pkg.fileSize,
    fileHash: pkg.fileHash,
    firmwareVersion: pkg.firmwareVersion,
    decision: evaluation.decision,
    reason: evaluation.reason,
    incidentId: evaluation.incidentId,
    checks: evaluation.checks,
    durationMs,
    animation,
    device: {
      id: updatedDevice.id,
      name: updatedDevice.name,
      model: updatedDevice.model,
      firmwareVersion: updatedDevice.firmware_version,
      minimumVersion: updatedDevice.minimum_version,
      status: updatedDevice.device_status,
      riskLevel: updatedDevice.risk_level
    }
  };
}

/**
 * Get server status and trial history
 */
export function getAutoUpdateServerStatus() {
  const allDevices = getDevices();
  const trials = getSimulationTrials(20);

  const todayIso = new Date().toISOString().split('T')[0];
  const trialsToday = trials.filter(t => t.timestamp.startsWith(todayIso));

  const validPassed = trialsToday.filter(t => t.decision === 'APPROVED').length;
  const invalidBlocked = trialsToday.filter(t => t.decision === 'REJECTED').length;

  return {
    serverStatus: 'ACTIVE',
    port: 3000,
    engine: 'Ed25519 & SHA-256 Automated Ingestion Server',
    sourceIp: '10.0.8.25 (OTA Staging Core)',
    totalTrialsToday: trialsToday.length,
    validPassedToday: validPassed,
    invalidBlockedToday: invalidBlocked,
    supportedDevices: allDevices.map(d => ({
      id: d.id,
      name: d.name,
      model: d.model,
      firmwareVersion: d.firmware_version,
      type: d.type
    })),
    recentTrials: trials.slice(0, 10)
  };
}
