// utils/hashing.js
// Argon2id password hashing with server-side pepper.
//
// Design:
//   - Argon2id = hybrid of Argon2i (side-channel resistant) and Argon2d
//     (GPU attack resistant). Winner of the 2015 Password Hashing
//     Competition and current OWASP recommendation.
//   - A per-user random SALT is generated automatically by the argon2
//     library and embedded in the output hash string. Salts defend
//     against rainbow tables and ensure two users with the same
//     password produce different hashes.
//   - A server-side PEPPER (from .env, never stored in DB) is appended
//     to the plaintext before hashing. This means an attacker who
//     steals only the database cannot crack hashes — they also need
//     access to the application server to read the pepper. Defence
//     in depth against DB-only breaches.

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

/**
 * Hashes a plaintext password using Argon2id with pepper and a
 * randomly-generated per-user salt (handled by the library).
 *
 * @param {string} plaintext — the user's chosen password
 * @returns {Promise<string>} — the full Argon2 hash string, including
 *   algorithm identifier, parameters, salt, and hash. Store this
 *   single string in the users.password_hash column.
 */
async function hashPassword(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new Error('Password must be a non-empty string.');
  }
  return argon2.hash(plaintext + PEPPER, ARGON2_OPTIONS);
}

/**
 * Verifies a plaintext password against a stored Argon2 hash.
 * Re-applies the pepper before verification. The salt and parameters
 * are extracted automatically from the stored hash by the library.
 *
 * @param {string} storedHash — the Argon2 hash string from the DB
 * @param {string} plaintext — the password the user just entered
 * @returns {Promise<boolean>} — true if the password matches
 */
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
