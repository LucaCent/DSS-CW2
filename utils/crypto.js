// AES-256-GCM encryption for sensitive columns (email, TOTP secret).
// We chose GCM over CBC because GCM gives you authenticated encryption —
// it produces an auth tag that lets you detect if the ciphertext was
// tampered with before you even try to decrypt. CBC just encrypts, no
// integrity check at all.
//
// Each encrypt() call generates a fresh random IV so the same plaintext
// won't produce the same ciphertext twice (important for GCM especially —
// reusing an IV with the same key completely breaks GCM's security).
//
// Everything gets packed into one string: iv:authTag:ciphertext (hex)
// so we only need one DB column per encrypted field.

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 12 bytes is the recommended IV size for GCM
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 64 hex chars → 32 bytes

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
