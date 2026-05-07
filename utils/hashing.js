/*
 * SECURITY: Password Hashing (Argon2id + pepper)
 * Attack prevented: Password cracking after a database breach
 * How it works: Argon2id is memory-hard (64 MB per attempt) so brute
 *   forcing is expensive even with a GPU. The argon2 library handles
 *   per-user salt generation automatically — it's embedded in the hash
 *   string, so the same password always produces a different output.
 *   A server-side pepper from .env is appended before hashing so a
 *   DB dump alone isn't enough to start cracking — the attacker needs
 *   the application environment too.
 */

const argon2 = require('argon2');
require('dotenv').config();

const PEPPER = process.env.PEPPER;

if (!PEPPER) {
  throw new Error('PEPPER environment variable is required but not set.');
}

// Argon2id tuning parameters.
//   memoryCost = 64 MB    — OWASP minimum recommendation
//   timeCost   = 3        — number of iterations
//   parallelism = 1       — single-thread (simpler, safer default)
// These values balance security with reasonable login response time
// (~100–300ms per hash on typical server hardware).
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,   // 65536 KiB = 64 MB
  timeCost: 3,
  parallelism: 1,
};

// Hash a password — returns the full Argon2 hash string (params + salt
// + hash all in one). Store it as-is in the DB.
async function hashPassword(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new Error('Password must be a non-empty string.');
  }
  return argon2.hash(plaintext + PEPPER, ARGON2_OPTIONS);
}

// Check a password against a stored hash. Argon2 pulls the salt and
// params out automatically. Returns false rather than throwing if the
// hash is malformed — cleaner for the callers.
async function verifyPassword(storedHash, plaintext) {
  if (typeof plaintext !== 'string' || typeof storedHash !== 'string') {
    return false;
  }
  try {
    return await argon2.verify(storedHash, plaintext + PEPPER);
  } catch (err) {
    // verify() throws on malformed hashes. Treat as a failed match
    // rather than leaking the error to the caller.
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };
