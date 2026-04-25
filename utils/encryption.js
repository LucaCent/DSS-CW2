// utils/encryption.js
// AES-256-GCM authenticated encryption for sensitive user fields.
// GCM is used (not CBC) because it provides built-in authentication —
// any tampering with the ciphertext is detected at decrypt time.

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // 12 bytes is the standard/recommended IV size for GCM
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8');

if (KEY.length !== 32) {
  throw new Error(
    `ENCRYPTION_KEY must be exactly 32 bytes. Got ${KEY.length} bytes.`
  );
}

/**
 * Encrypts a plaintext string.
 * Returns a single string in the format: iv:authTag:ciphertext (all hex).
 * Storing all three parts together means decryption only needs one DB column.
 */
function encryptData(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;

  // IV must be random and unique per encryption — NEVER reuse with the same key
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts a string produced by encryptData.
 * Throws if the auth tag fails to verify — meaning the data was tampered with
 * or the wrong key was used.
 */
function decryptData(payload) {
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

module.exports = { encryptData, decryptData };