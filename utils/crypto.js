/**
 * SECURITY: AES-256 Encryption / Decryption Helpers
 * Attack prevented: Data breach / data leakage
 * How it works: Sensitive fields (e.g. email addresses, TOTP secrets) are
 *   encrypted at the application layer using AES-256-CBC before being
 *   written to PostgreSQL. Even if an attacker gains direct database
 *   access, the data is unreadable without the encryption key.
 *
 * Key management:
 *   - The encryption key is stored in the .env file as a 64-character
 *     hex string (32 bytes), NEVER hardcoded in source code.
 *   - The .env file is excluded from version control via .gitignore.
 *   - Each encryption operation generates a random 16-byte IV (initialisation
 *     vector) to ensure identical plaintexts produce different ciphertexts.
 *   - The IV is prepended to the ciphertext and stored together.
 *
 * Library used: Node.js built-in crypto module — no third-party dependency
 *   needed for standard AES-256-CBC encryption.
 */

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-cbc';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes

/**
 * Encrypt a plaintext string using AES-256-CBC.
 * Returns a string in the format: iv_hex:ciphertext_hex
 */
function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

/**
 * Decrypt a ciphertext string (iv_hex:ciphertext_hex) back to plaintext.
 */
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

/**
 * Hash a string using SHA-256. Used for password reset tokens —
 * the token is sent to the user in plaintext, but only its hash
 * is stored in the database. This way, even if the DB is compromised,
 * the raw token cannot be recovered.
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { encrypt, decrypt, hashToken };
