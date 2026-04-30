/*
 * SECURITY: Database Encryption (AES-256-CBC)
 * Attack prevented: Data leakage if the database is compromised
 * How it works: Personally identifiable fields (emails, TOTP secrets)
 *   are encrypted here before being stored in Postgres. The key lives
 *   in .env (64 hex chars = 32 bytes) and is never committed to source
 *   control. A fresh random IV is generated per encrypt() call so the
 *   same plaintext never produces the same ciphertext twice.
 *
 * Uses the built-in Node.js crypto module — no extra dependency needed.
 */

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-cbc';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes

// Encrypt plaintext -> "iv_hex:ciphertext_hex"
function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Decrypt "iv_hex:ciphertext_hex" -> plaintext
function decrypt(ciphertext) {
  if (!ciphertext) return null;
  const parts = ciphertext.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// SHA-256 hash — used for password reset tokens so we only
// store the hash in the DB, not the raw token itself.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { encrypt, decrypt, hashToken };
