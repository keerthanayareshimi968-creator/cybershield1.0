import { getDatabase } from '../database/db.js';
import { initializeKeys } from '../security/crypto.js';

async function main() {
  console.log('--- IoT CyberShield: Generating Development Ed25519 Keys ---');
  await getDatabase();
  await initializeKeys();
  console.log('✓ Successfully initialized dev-ed25519-primary and dev-ed25519-secondary');
  console.log('✓ Keystore ready.');
  process.exit(0);
}

main().catch(err => {
  console.error('Key generation error:', err);
  process.exit(1);
});
