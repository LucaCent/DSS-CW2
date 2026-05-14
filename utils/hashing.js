// Password hashing with Argon2id.
// Picked Argon2id over bcrypt because it won the 2015 Password Hashing
// Competition and OWASP now recommends it. The "id" variant is a hybrid —
// it's resistant to side-channel attacks (like Argon2i) AND GPU attacks
// (like Argon2d). bcrypt doesn't have the memory-hardness that makes
// GPU cracking expensive.
//
// Three layers of protection:
//   salt   — auto-generated per hash by the library, defeats rainbow tables
//   pepper — appended from .env before hashing, so a DB dump alone is useless
//   argon2id — 64MB memory per attempt, makes brute force very slow

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

// Hash a password
async function hashPassword(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new Error('Password must be a non-empty string.');
  }
  return argon2.hash(plaintext + PEPPER, ARGON2_OPTIONS);
}

// Check a password against a stored hash.
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
