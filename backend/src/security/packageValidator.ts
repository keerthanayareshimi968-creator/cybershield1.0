import JSZip from 'jszip';
import { calculateSha256, canonicalizeJson, verifyEd25519, compareVersions } from './crypto.js';
import { getDatabase, queryOne, execute } from '../database/db.js';

export interface ManifestData {
  packageFormatVersion: string;
  deviceType: string;
  firmwareVersion: string;
  minimumSupportedVersion: string;
  firmwareSha256: string;
  updateId: string;
  keyId: string;
  buildTimestamp?: string;
  vendor?: string;
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
  manifest?: ManifestData;
  calculatedHash?: string;
  targetDeviceId: string;
  previousVersion: string;
  proposedVersion: string;
  updateId: string;
  isSimulatedDemo?: boolean;
}

export async function validateAndVerifyFirmware(
  fileBuffer: Buffer,
  deviceId: string,
  fileName: string
): Promise<VerificationResult> {
  const db = await getDatabase();
  const checks: VerificationCheck[] = [];
  const now = new Date().toISOString();

  const addCheck = (
    id: string,
    name: string,
    category: VerificationCheck['category'],
    status: VerificationCheck['status'],
    detail: string
  ) => {
    checks.push({ id, name, category, status, detail, timestamp: new Date().toISOString() });
  };

  // 1. Fetch Target Device
  const device = queryOne<{
    id: string;
    name: string;
    type: string;
    firmware_version: string;
    minimum_version: string;
    device_status: string;
  }>(db, 'SELECT id, name, type, firmware_version, minimum_version, device_status FROM devices WHERE id = ?', [deviceId]);

  if (!device) {
    addCheck('DEVICE_EXISTS', 'Target Device Existence', 'COMPATIBILITY', 'FAILED', `Virtual device with ID '${deviceId}' was not found.`);
    return {
      decision: 'REJECTED',
      reason: `Target virtual device '${deviceId}' does not exist.`,
      checks,
      targetDeviceId: deviceId,
      previousVersion: 'UNKNOWN',
      proposedVersion: 'UNKNOWN',
      updateId: 'N/A',
    };
  }

  // 2. Unpack & Validate ZIP package structure
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(fileBuffer);
  } catch (err: any) {
    addCheck('ZIP_STRUCTURE', 'Firmware Package Archive', 'STRUCTURE', 'FAILED', 'Uploaded file is not a valid ZIP archive or is corrupt.');
    return {
      decision: 'REJECTED',
      reason: 'Package is not a valid ZIP file. Safe OTA requires a signed container (.zip).',
      checks,
      targetDeviceId: device.id,
      previousVersion: device.firmware_version,
      proposedVersion: 'UNKNOWN',
      updateId: 'N/A',
    };
  }

  // Check for malicious paths in ZIP (zip slip protection)
  const fileNames = Object.keys(zip.files);
  for (const name of fileNames) {
    if (name.includes('..') || name.startsWith('/') || name.startsWith('\\')) {
      addCheck('ZIP_SECURITY', 'Path Traversal Guard', 'STRUCTURE', 'FAILED', `Malicious relative or absolute path detected: '${name}'`);
      return {
        decision: 'REJECTED',
        reason: 'Path traversal / zip slip pattern detected in archive entries.',
        checks,
        targetDeviceId: device.id,
        previousVersion: device.firmware_version,
        proposedVersion: 'UNKNOWN',
        updateId: 'N/A',
      };
    }
  }

  // Check required entries
  const manifestFile = zip.file('manifest.json');
  const firmwareBinFile = zip.file('firmware.bin');
  const signatureFile = zip.file('firmware.sig');

  if (!manifestFile || !firmwareBinFile || !signatureFile) {
    const missing = [
      !manifestFile ? 'manifest.json' : null,
      !firmwareBinFile ? 'firmware.bin' : null,
      !signatureFile ? 'firmware.sig' : null,
    ].filter(Boolean);

    addCheck(
      'REQUIRED_FILES',
      'Mandatory Package Files',
      'STRUCTURE',
      'FAILED',
      `Missing mandatory container files: ${missing.join(', ')}.`
    );
    return {
      decision: 'REJECTED',
      reason: `Malformed firmware package container. Missing: ${missing.join(', ')}.`,
      checks,
      targetDeviceId: device.id,
      previousVersion: device.firmware_version,
      proposedVersion: 'UNKNOWN',
      updateId: 'N/A',
    };
  }

  addCheck('PACKAGE_STRUCTURE', 'Container Integrity', 'STRUCTURE', 'PASSED', 'ZIP archive is well-formed with manifest.json, firmware.bin, and firmware.sig.');

  // 3. Parse manifest
  let manifest: ManifestData;
  try {
    const manifestStr = await manifestFile.async('text');
    manifest = JSON.parse(manifestStr);
  } catch (err: any) {
    addCheck('MANIFEST_VALIDATION', 'Manifest JSON Schema', 'STRUCTURE', 'FAILED', `Failed to parse manifest.json: ${err.message}`);
    return {
      decision: 'REJECTED',
      reason: 'manifest.json is not valid JSON.',
      checks,
      targetDeviceId: device.id,
      previousVersion: device.firmware_version,
      proposedVersion: 'UNKNOWN',
      updateId: 'N/A',
    };
  }

  // Validate required manifest fields
  const requiredFields = ['packageFormatVersion', 'deviceType', 'firmwareVersion', 'minimumSupportedVersion', 'firmwareSha256', 'updateId', 'keyId'];
  const missingManifestProps = requiredFields.filter(f => !(f in manifest) || !(manifest as any)[f]);

  if (missingManifestProps.length > 0) {
    addCheck(
      'MANIFEST_SCHEMA',
      'Manifest Field Completeness',
      'STRUCTURE',
      'FAILED',
      `Manifest is missing required attributes: ${missingManifestProps.join(', ')}`
    );
    return {
      decision: 'REJECTED',
      reason: `Manifest schema violation: missing ${missingManifestProps.join(', ')}.`,
      checks,
      manifest,
      targetDeviceId: device.id,
      previousVersion: device.firmware_version,
      proposedVersion: manifest.firmwareVersion || 'UNKNOWN',
      updateId: manifest.updateId || 'N/A',
    };
  }

  addCheck('MANIFEST_SCHEMA', 'Manifest Schema Validation', 'STRUCTURE', 'PASSED', `Manifest v${manifest.packageFormatVersion} conforms to IoT CyberShield secure specification.`);

  // 4. Calculate actual SHA-256 from firmware.bin bytes
  const firmwareBuffer = await firmwareBinFile.async('nodebuffer');
  const actualHash = calculateSha256(firmwareBuffer);

  const hashMatch = actualHash.toLowerCase() === manifest.firmwareSha256.toLowerCase();
  if (!hashMatch) {
    addCheck(
      'SHA256_HASH',
      'Firmware Binary Hash Verification',
      'INTEGRITY',
      'FAILED',
      `Calculated hash (${actualHash.substring(0, 16)}...) differs from manifest (${manifest.firmwareSha256.substring(0, 16)}...). Firmware altered in transit or corrupted.`
    );
  } else {
    addCheck(
      'SHA256_HASH',
      'Firmware Binary Hash Verification',
      'INTEGRITY',
      'PASSED',
      `Calculated SHA-256 matches manifest exactly: ${actualHash}`
    );
  }

  // 5. Verify Ed25519 digital signature
  const signatureHex = (await signatureFile.async('text')).trim();
  // Build canonical manifest representation (everything in manifest except any signature field)
  const canonicalBytes = canonicalizeJson({
    packageFormatVersion: manifest.packageFormatVersion,
    deviceType: manifest.deviceType,
    firmwareVersion: manifest.firmwareVersion,
    minimumSupportedVersion: manifest.minimumSupportedVersion,
    firmwareSha256: manifest.firmwareSha256,
    updateId: manifest.updateId,
    keyId: manifest.keyId,
    vendor: manifest.vendor || 'CyberShield-Secure-IoT',
  });

  const sigResult = await verifyEd25519(canonicalBytes, signatureHex, manifest.keyId);
  if (!sigResult.verified) {
    addCheck(
      'ED25519_SIGNATURE',
      'Ed25519 Digital Signature Authenticity',
      'AUTHENTICITY',
      'FAILED',
      sigResult.error || 'Invalid digital signature.'
    );
  } else {
    addCheck(
      'ED25519_SIGNATURE',
      'Ed25519 Digital Signature Authenticity',
      'AUTHENTICITY',
      'PASSED',
      `Cryptographically verified using trusted key '${manifest.keyId}' (${sigResult.keyName}).`
    );
  }

  // 6. Device compatibility check
  const typeMatch = device.type === manifest.deviceType;
  if (!typeMatch) {
    addCheck(
      'DEVICE_COMPATIBILITY',
      'Hardware Device Type Matching',
      'COMPATIBILITY',
      'FAILED',
      `Package target type '${manifest.deviceType}' does not match device type '${device.type}'. Prevents cross-device flashing.`
    );
  } else {
    addCheck(
      'DEVICE_COMPATIBILITY',
      'Hardware Device Type Matching',
      'COMPATIBILITY',
      'PASSED',
      `Package target '${manifest.deviceType}' is fully compatible with node '${device.name}'.`
    );
  }

  // 7. Version & Rollback protection policy
  const allowEmergencySetting = queryOne<{ value: string }>(
    db,
    "SELECT value FROM application_settings WHERE key = 'allow_emergency_downgrade'"
  );
  const allowEmergency = allowEmergencySetting?.value === 'true';

  const isUpgrade = compareVersions(manifest.firmwareVersion, device.firmware_version) > 0;
  const meetsDeviceMin = compareVersions(manifest.firmwareVersion, device.minimum_version) >= 0;
  const meetsPackageMin = compareVersions(manifest.firmwareVersion, manifest.minimumSupportedVersion) >= 0;

  if (!isUpgrade && !allowEmergency) {
    addCheck(
      'ROLLBACK_PROTECTION',
      'Monotonic Version & Rollback Protection',
      'POLICY',
      'FAILED',
      `Proposed version ${manifest.firmwareVersion} is not strictly greater than current version ${device.firmware_version}. Unauthorized downgrade blocked.`
    );
  } else if (!meetsDeviceMin) {
    addCheck(
      'ROLLBACK_PROTECTION',
      'Monotonic Version & Rollback Protection',
      'POLICY',
      'FAILED',
      `Proposed version ${manifest.firmwareVersion} violates device hardware minimum version policy (${device.minimum_version}).`
    );
  } else if (!meetsPackageMin) {
    addCheck(
      'ROLLBACK_PROTECTION',
      'Monotonic Version & Rollback Protection',
      'POLICY',
      'FAILED',
      `Proposed version ${manifest.firmwareVersion} violates package minimum supported version (${manifest.minimumSupportedVersion}).`
    );
  } else {
    addCheck(
      'ROLLBACK_PROTECTION',
      'Monotonic Version & Rollback Protection',
      'POLICY',
      'PASSED',
      `Version ${manifest.firmwareVersion} is a valid monotonic upgrade over ${device.firmware_version} (min: ${device.minimum_version}).`
    );
  }

  // 8. Replay Protection check
  const alreadyAccepted = queryOne(
    db,
    'SELECT 1 FROM accepted_update_ids WHERE device_id = ? AND update_id = ?',
    [device.id, manifest.updateId]
  );

  if (alreadyAccepted) {
    addCheck(
      'REPLAY_PROTECTION',
      'Anti-Replay Token Validation',
      'REPLAY',
      'FAILED',
      `Update ID '${manifest.updateId}' was previously accepted for this device. Potential network replay attack blocked.`
    );
  } else {
    addCheck(
      'REPLAY_PROTECTION',
      'Anti-Replay Token Validation',
      'REPLAY',
      'PASSED',
      `Update ID '${manifest.updateId}' is unique and unused for node '${device.id}'.`
    );
  }

  // Final Decision Synthesis
  const anyFailed = checks.some(c => c.status === 'FAILED');
  const decision: 'APPROVED' | 'REJECTED' = anyFailed ? 'REJECTED' : 'APPROVED';

  const failedReasons = checks.filter(c => c.status === 'FAILED').map(c => `${c.name}: ${c.detail}`);
  const reason = anyFailed ? failedReasons.join(' | ') : 'All mandatory security checks passed.';

  return {
    decision,
    reason,
    checks,
    manifest,
    calculatedHash: actualHash,
    targetDeviceId: device.id,
    previousVersion: device.firmware_version,
    proposedVersion: manifest.firmwareVersion,
    updateId: manifest.updateId,
  };
}
