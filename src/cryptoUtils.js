import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, '..', 'data');
const keysFile = path.join(dataDir, 'dev_keys.json');

// In-memory cache of private keys (NEVER exposed to client)
const backendPrivateKeys = new Map();

/**
 * Initialize development keys from data/dev_keys.json or generate new ones
 */
export function initKeystore() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  let fileKeys = {};
  if (fs.existsSync(keysFile)) {
    try {
      fileKeys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
    } catch {
      fileKeys = {};
    }
  }

  // Load existing keys
  for (const [keyId, keyData] of Object.entries(fileKeys)) {
    if (keyData.privateKeyPem) {
      backendPrivateKeys.set(keyId, keyData.privateKeyPem);
    }
  }

  // Ensure dev-ed25519-primary exists
  if (!backendPrivateKeys.has('dev-ed25519-primary')) {
    const pair = generateEd25519KeyPair('dev-ed25519-primary', 'Primary Hardware Root Signer (Dev)');
    fileKeys['dev-ed25519-primary'] = pair;
    backendPrivateKeys.set('dev-ed25519-primary', pair.privateKeyPem);
  }

  // Ensure dev-ed25519-secondary exists
  if (!backendPrivateKeys.has('dev-ed25519-secondary')) {
    const pair = generateEd25519KeyPair('dev-ed25519-secondary', 'Secondary Field Update Signer (Dev)');
    fileKeys['dev-ed25519-secondary'] = pair;
    backendPrivateKeys.set('dev-ed25519-secondary', pair.privateKeyPem);
  }

  // Save back to file
  try {
    fs.writeFileSync(keysFile, JSON.stringify(fileKeys, null, 2));
  } catch (err) {
    console.warn('[Crypto] Could not write keys file:', err.message);
  }

  return fileKeys;
}

/**
 * Generate a new Ed25519 key pair
 */
export function generateEd25519KeyPair(keyId, name) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const publicKeyDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  const rawPublicKeyHex = publicKeyDer.subarray(publicKeyDer.length - 32).toString('hex');

  backendPrivateKeys.set(keyId, privateKey);

  return {
    keyId,
    name,
    publicKeyHex: rawPublicKeyHex,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    createdAt: new Date().toISOString()
  };
}

/**
 * Calculate SHA-256 hex digest over bytes or string
 */
export function calculateSha256(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Verify an Ed25519 signature
 */
export function verifyEd25519Signature(data, signature, publicKeyInput) {
  try {
    const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    let sigBuf = signature;
    if (typeof signature === 'string') {
      sigBuf = /^[0-9a-fA-F]+$/.test(signature) ? Buffer.from(signature, 'hex') : Buffer.from(signature, 'base64');
    }

    let pubKeyObj;
    if (typeof publicKeyInput === 'string' && publicKeyInput.includes('-----BEGIN PUBLIC KEY-----')) {
      pubKeyObj = crypto.createPublicKey(publicKeyInput);
    } else {
      // Reconstruct DER SPKI from 32-byte raw hex or buffer
      let rawPubBuf = Buffer.isBuffer(publicKeyInput) ? publicKeyInput : Buffer.from(publicKeyInput, 'hex');
      if (rawPubBuf.length === 32) {
        // Standard Ed25519 SPKI DER prefix is 12 bytes: 302a300506032b6570032100
        const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
        const fullDer = Buffer.concat([spkiPrefix, rawPubBuf]);
        pubKeyObj = crypto.createPublicKey({ key: fullDer, format: 'der', type: 'spki' });
      } else {
        pubKeyObj = crypto.createPublicKey(publicKeyInput);
      }
    }

    return crypto.verify(null, dataBuf, pubKeyObj, sigBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Sign data with an in-memory private key (backend only, for test package generation)
 */
export function signWithEd25519(data, keyId) {
  const privateKeyPem = backendPrivateKeys.get(keyId);
  if (!privateKeyPem) {
    throw new Error(`Signing private key '${keyId}' is not available.`);
  }

  const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const privateKeyObj = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, dataBuf, privateKeyObj);
}

/**
 * Compare semantic versions (e.g., '2.1.0' vs '2.0.0')
 */
export function compareVersions(a, b) {
  const aa = String(a).replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0);
  const bb = String(b).replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0);
  const len = Math.max(aa.length, bb.length);
  for (let i = 0; i < len; i++) {
    const diff = (aa[i] || 0) - (bb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
