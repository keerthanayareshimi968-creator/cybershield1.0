import fs from 'fs';
import path from 'path';
import { getDatabase } from '../database/db.js';
import { initializeKeys } from '../security/crypto.js';
import { generateFirmwarePackage } from '../services/packageGenerator.js';

async function main() {
  console.log('--- IoT CyberShield: Generating Sample Test Firmware Packages ---');
  await getDatabase();
  await initializeKeys();

  const outDir = path.resolve(process.cwd(), 'test-packages');
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const scenarios: Array<{
    scenario: 'valid' | 'invalid_signature' | 'modified_firmware' | 'downgrade' | 'unknown_key' | 'malformed';
    desc: string;
  }> = [
    { scenario: 'valid', desc: 'Valid authentic signed firmware update (Expected: APPROVED)' },
    { scenario: 'invalid_signature', desc: 'Corrupted digital signature bytes (Expected: REJECTED)' },
    { scenario: 'modified_firmware', desc: 'Firmware binary tampered after signing (Expected: REJECTED)' },
    { scenario: 'downgrade', desc: 'Firmware downgrade violating monotonic policy (Expected: REJECTED)' },
    { scenario: 'unknown_key', desc: 'Signed by untrusted rogue key identifier (Expected: REJECTED)' },
    { scenario: 'malformed', desc: 'Malformed archive lacking manifest (Expected: REJECTED)' },
  ];

  for (const s of scenarios) {
    const pkg = await generateFirmwarePackage({
      deviceId: 'DEV-CAM-01',
      scenario: s.scenario,
    });
    const filePath = path.join(outDir, pkg.fileName);
    fs.writeFileSync(filePath, pkg.buffer);
    console.log(`✓ Generated ${pkg.fileName} [${s.desc}]`);
  }

  // Also write plain-text test sample
  const textSample = path.join(outDir, 'safe_firmware_test.txt');
  fs.writeFileSync(
    textSample,
    'SAFE_FIRMWARE_TEST_FILE\nThis file is a harmless plain-text file. It is NOT valid deployable binary firmware.\nIoT CyberShield must identify this as text and reject it from firmware installation.'
  );
  console.log('✓ Generated safe_firmware_test.txt (Harmless text sample)');
  console.log(`\nAll sample packages generated in ${outDir}`);
  process.exit(0);
}

main().catch(err => {
  console.error('Package generation error:', err);
  process.exit(1);
});
