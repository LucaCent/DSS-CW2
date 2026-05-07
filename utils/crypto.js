/*
 * SECURITY: Database Encryption (AES-256-GCM)
 * Attack prevented: Data leakage if the database is compromised
 * How it works: Personally identifiable fields (emails, TOTP secrets)
 *   are encrypted here before being stored in Postgres. The key lives
 *   in .env and is never committed to source control. A fresh random
 *   IV is generated per encrypt() call so the same plaintext never
 *   produces the same ciphertext twice.
 *
 * GCM mode is used rather than CBC because it provides authenticated
 * encryption — the auth tag detects any tampering with the ciphertext
 * before decryption even starts. CBC has no such guarantee.
 *
 * Stored format: iv:authTag:ciphertext (all hex, separated by ':')
 *
 * Uses the built-in Node.js crypto module — no extra dependency needed.
 */

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 12 bytes is the recommended IV size for GCM
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8'); // 32 bytes

if (KEY.length !== 32) {
  throw new Error(`ENCRYPTION_KEY must be exactly 32 bytes. Got ${KEY.length} bytes.`);
}

// Encrypt plaintext -> "iv_hex:authTag_hex:ciphertext_hex"
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;

  // IV must be random and unique per encryption — never reuse with the same key
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

// Decrypt "iv_hex:authTag_hex:ciphertext_hex" -> plaintext
// Throws if the auth tag fails to verify — meaning the data was tampered
// with or the wrong key was used.
function decrypt(payload) {
  if (payload === null || payload === undefined) return null;

  const parts = payload.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted payload format');
  }

  const [ivHex, authTagHex, ciphertextHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return decrypted.toString('utf8');
}

// SHA-256 hash — used for password reset tokens so we only
// store the hash in the DB, not the raw token itself.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { encrypt, decrypt, hashToken };
