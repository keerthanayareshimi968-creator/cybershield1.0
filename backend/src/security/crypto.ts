import crypto from 'crypto';
import { getDatabase, query, queryOne, execute } from '../database/db.js';

import fs from 'fs';
import path from 'path';

export interface KeyPairInfo {
  keyId: string;
  name: string;
  publicKeyHex: string;
  privateKeyPem: string; // kept securely in server memory/file, never returned to client
}

const KEYS_DIR = path.resolve(process.cwd(), 'data');
const KEYS_FILE = path.join(KEYS_DIR, 'dev_keys.json');

// In-memory server-side private key cache for development test package generation
const devPrivateKeys = new Map<string, string>();

/**
 * Generate a new Ed25519 key pair
 */
export function generateEd25519KeyPair(keyId: string, name: string): KeyPairInfo {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Export raw public key as hex for compact representation
  const publicKeyDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  // The last 32 bytes of standard Ed25519 SPKI DER are the raw public key
  const rawPublicKeyHex = publicKeyDer.subarray(publicKeyDer.length - 32).toString('hex');

  const info: KeyPairInfo = {
    keyId,
    name,
    publicKeyHex: rawPublicKeyHex,
    privateKeyPem: privateKey,
  };

  devPrivateKeys.set(keyId, privateKey);
  return info;
}

/**
 * Initialize development keys in the database and local persistent keystore
 */
export async function initializeKeys(): Promise<void> {
  const db = await getDatabase();
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  let fileKeys: Record<string, KeyPairInfo> = {};
  if (fs.existsSync(KEYS_FILE)) {
    try {
      fileKeys = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf-8'));
    } catch {
      fileKeys = {};
    }
  }

  // Helper to ensure key exists in fileKeys and in devPrivateKeys
  const ensureKey = (keyId: string, name: string): KeyPairInfo => {
    if (fileKeys[keyId] && fileKeys[keyId].privateKeyPem && fileKeys[keyId].publicKeyHex) {
      devPrivateKeys.set(keyId, fileKeys[keyId].privateKeyPem);
      return fileKeys[keyId];
    }
    const generated = generateEd25519KeyPair(keyId, name);
    fileKeys[keyId] = generated;
    return generated;
  };

  const primaryKey = ensureKey('dev-ed25519-primary', 'Primary Hardware Root Signer (Dev)');
  const secondaryKey = ensureKey('dev-ed25519-secondary', 'Secondary Field Update Signer (Dev)');
  ensureKey('untrusted-rogue-key-999', 'Adversary Unauthorized Signer');

  // Save persistent fileKeys
  fs.writeFileSync(KEYS_FILE, JSON.stringify(fileKeys, null, 2));

  // Sync to trusted_signing_keys table (using INSERT OR REPLACE)
  const now = new Date().toISOString();
  execute(
    db,
    `INSERT OR REPLACE INTO trusted_signing_keys (key_id, name, public_key_hex, algorithm, is_active, is_revoked, created_at)
     VALUES (?, ?, ?, 'Ed25519', 1, 0, ?)`,
    [primaryKey.keyId, primaryKey.name, primaryKey.publicKeyHex, now]
  );
  execute(
    db,
    `INSERT OR REPLACE INTO trusted_signing_keys (key_id, name, public_key_hex, algorithm, is_active, is_revoked, created_at)
     VALUES (?, ?, ?, 'Ed25519', 1, 0, ?)`,
    [secondaryKey.keyId, secondaryKey.name, secondaryKey.publicKeyHex, now]
  );
}

/**
 * Get private key for a key ID (server-side only for package generator)
 */
export function getDevPrivateKey(keyId: string): string | undefined {
  return devPrivateKeys.get(keyId);
}

/**
 * Calculate SHA-256 hash of a buffer
 */
export function calculateSha256(data: Buffer | Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Canonical deterministic JSON representation for signing
 * Recursively sorts keys so identical objects produce identical byte arrays
 */
export function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const parts = sortedKeys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return '{' + parts.join(',') + '}';
}

/**
 * Sign data using Ed25519 private key
 */
export function signEd25519(data: Buffer | string, privateKeyPem: string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, buf, privateKey);
  return signature.toString('hex');
}

/**
 * Verify Ed25519 signature
 */
export async function verifyEd25519(
  data: Buffer | string,
  signatureHex: string,
  keyId: string
): Promise<{ verified: boolean; error?: string; keyName?: string }> {
  try {
    const db = await getDatabase();
    const keyRecord = queryOne<{ key_id: string; name: string; public_key_hex: string; is_active: number; is_revoked: number }>(
      db,
      'SELECT key_id, name, public_key_hex, is_active, is_revoked FROM trusted_signing_keys WHERE key_id = ?',
      [keyId]
    );

    if (!keyRecord) {
      return { verified: false, error: `Key identifier '${keyId}' is not found in trusted keystore.` };
    }
    if (keyRecord.is_revoked === 1) {
      return { verified: false, error: `Key identifier '${keyId}' has been revoked.` };
    }
    if (keyRecord.is_active !== 1) {
      return { verified: false, error: `Key identifier '${keyId}' is currently inactive.` };
    }

    const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const sigBuffer = Buffer.from(signatureHex, 'hex');

    // Reconstruct SPKI DER from 32-byte raw Ed25519 public key:
    // RFC 8410 ASN.1 Prefix for Ed25519 SubjectPublicKeyInfo (12 bytes):
    // 30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte-public-key>
    const ed25519SpkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const rawKey = Buffer.from(keyRecord.public_key_hex, 'hex');
    const fullSpkiDer = Buffer.concat([ed25519SpkiPrefix, rawKey]);

    const publicKey = crypto.createPublicKey({
      key: fullSpkiDer,
      format: 'der',
      type: 'spki',
    });

    const isVerified = crypto.verify(null, buf, publicKey, sigBuffer);
    if (!isVerified) {
      return { verified: false, error: 'Cryptographic signature verification failed. Bytes were altered or signed with an incorrect key.' };
    }

    return { verified: true, keyName: keyRecord.name };
  } catch (err: any) {
    return { verified: false, error: `Signature verification exception: ${err.message}` };
  }
}

/**
 * Compare two numeric semantic versions (major.minor.patch)
 * Returns >0 if a > b, <0 if a < b, 0 if equal
 */
export function compareVersions(a: string, b: string): number {
  const cleanA = a.replace(/^v/i, '').trim();
  const cleanB = b.replace(/^v/i, '').trim();

  const segA = cleanA.split('.').map(n => parseInt(n, 10) || 0);
  const segB = cleanB.split('.').map(n => parseInt(n, 10) || 0);

  const len = Math.max(segA.length, segB.length);
  for (let i = 0; i < len; i++) {
    const partA = segA[i] || 0;
    const partB = segB[i] || 0;
    if (partA !== partB) {
      return partA - partB;
    }
  }
  return 0;
}
