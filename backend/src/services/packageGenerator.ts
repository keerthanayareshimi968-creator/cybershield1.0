import JSZip from 'jszip';
import crypto from 'crypto';
import { calculateSha256, canonicalizeJson, signEd25519, getDevPrivateKey } from '../security/crypto.js';
import { getDatabase, queryOne } from '../database/db.js';

export interface GeneratePackageOptions {
  deviceId: string;
  scenario?: 'valid' | 'invalid_signature' | 'modified_firmware' | 'downgrade' | 'unknown_key' | 'malformed' | 'replay';
  overrideVersion?: string;
  overrideUpdateId?: string;
}

export async function generateFirmwarePackage(options: GeneratePackageOptions): Promise<{
  buffer: Buffer;
  fileName: string;
  manifest: any;
  scenario: string;
  description: string;
  expectedResult: 'APPROVED' | 'REJECTED';
}> {
  const db = await getDatabase();
  const device = queryOne<{
    id: string;
    name: string;
    type: string;
    firmware_version: string;
    minimum_version: string;
  }>(db, 'SELECT id, name, type, firmware_version, minimum_version FROM devices WHERE id = ?', [options.deviceId]);

  if (!device) {
    throw new Error(`Device '${options.deviceId}' not found.`);
  }

  const scenario = options.scenario || 'valid';
  const zip = new JSZip();

  // Create simulated binary payload (harmless ARM Cortex-M simulated image bytes)
  const binaryPayload = Buffer.concat([
    Buffer.from('CYBERSHIELD-FIRMWARE-IMAGE-v2\0', 'utf-8'),
    crypto.randomBytes(1024),
  ]);

  // Version calculation:
  // If valid, increment patch or minor
  const versionParts = device.firmware_version.split('.').map(n => parseInt(n, 10) || 0);
  let targetVersion = `${versionParts[0]}.${versionParts[1]}.${(versionParts[2] || 0) + 1}`;
  if (scenario === 'downgrade') {
    // Propose an older version than device's current version
    targetVersion = `${Math.max(0, versionParts[0] - 1)}.0.0`;
    if (targetVersion === '0.0.0') targetVersion = '0.9.0';
  } else if (options.overrideVersion) {
    targetVersion = options.overrideVersion;
  }

  const updateId = options.overrideUpdateId || `UPD-${crypto.randomUUID().substring(0, 8).toUpperCase()}`;

  let keyId = 'dev-ed25519-primary';
  if (scenario === 'unknown_key') {
    keyId = 'untrusted-rogue-key-999';
  }

  let expectedResult: 'APPROVED' | 'REJECTED' = 'APPROVED';
  let description = 'Valid production-ready signed firmware update.';

  // If malformed scenario
  if (scenario === 'malformed') {
    zip.file('corrupt_readme.txt', 'This is a malformed package lacking manifest.json and signature.');
    const buf = await zip.generateAsync({ type: 'nodebuffer' });
    return {
      buffer: buf,
      fileName: `firmware_${device.id}_malformed.zip`,
      manifest: null,
      scenario,
      description: 'Malformed ZIP container missing required manifest and signature files.',
      expectedResult: 'REJECTED',
    };
  }

  // Calculate actual binary hash
  let actualBinary = binaryPayload;
  let hashInManifest = calculateSha256(actualBinary);

  if (scenario === 'modified_firmware') {
    // Modify the binary after hash has been written to manifest
    actualBinary = Buffer.concat([binaryPayload, Buffer.from('\xDE\xAD\xBE\xEF', 'binary')]);
    expectedResult = 'REJECTED';
    description = 'Firmware binary was modified post-signing; hash mismatch will be detected.';
  } else if (scenario === 'invalid_signature') {
    expectedResult = 'REJECTED';
    description = 'Digital signature corrupted; signature verification will fail.';
  } else if (scenario === 'downgrade') {
    expectedResult = 'REJECTED';
    description = `Unauthorized firmware downgrade to ${targetVersion} from current ${device.firmware_version}.`;
  } else if (scenario === 'unknown_key') {
    expectedResult = 'REJECTED';
    description = 'Signed by untrusted rogue key identifier not present in keystore.';
  } else if (scenario === 'replay') {
    expectedResult = 'REJECTED';
    description = `Replaying already processed update ID '${updateId}'.`;
  }

  const manifest = {
    packageFormatVersion: '1.0',
    deviceType: device.type,
    firmwareVersion: targetVersion,
    minimumSupportedVersion: device.minimum_version,
    firmwareSha256: hashInManifest,
    updateId,
    keyId,
    buildTimestamp: new Date().toISOString(),
    vendor: 'CyberShield-Secure-IoT',
  };

  // Canonicalize and sign manifest
  const canonicalBytes = canonicalizeJson({
    packageFormatVersion: manifest.packageFormatVersion,
    deviceType: manifest.deviceType,
    firmwareVersion: manifest.firmwareVersion,
    minimumSupportedVersion: manifest.minimumSupportedVersion,
    firmwareSha256: manifest.firmwareSha256,
    updateId: manifest.updateId,
    keyId: manifest.keyId,
    vendor: manifest.vendor,
  });

  const privateKey = getDevPrivateKey(keyId);
  if (!privateKey) {
    throw new Error(`Private key for keyId '${keyId}' is unavailable.`);
  }

  let signatureHex = signEd25519(canonicalBytes, privateKey);

  if (scenario === 'invalid_signature') {
    // Corrupt last 8 characters of signature
    signatureHex = signatureHex.substring(0, signatureHex.length - 8) + '00112233';
  }

  zip.file('manifest.json', JSON.stringify(manifest, null, 2));
  zip.file('firmware.bin', actualBinary);
  zip.file('firmware.sig', signatureHex);

  const zipBuffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  return {
    buffer: zipBuffer,
    fileName: `firmware_${device.id}_v${targetVersion}_${scenario}.zip`,
    manifest,
    scenario,
    description,
    expectedResult,
  };
}
