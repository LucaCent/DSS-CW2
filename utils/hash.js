const argon2 = require('argon2');
require('dotenv').config();

const PEPPER = process.env.PEPPER;

// Checks password meets strength requirements before hashing
function validatePasswordStrength(password) {
  const errors = [];

  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return errors; // empty array means password is valid
}

// Appends pepper to password then hashes using Argon2id
async function hashPassword(plainPassword) {
  const pepperedPassword = plainPassword + PEPPER;

  const hash = await argon2.hash(pepperedPassword, {
    type: argon2.argon2id,  // specifically argon2id as required by the brief
    memoryCost: 2 ** 16,    // 64MB memory — makes brute force expensive
    timeCost: 3,            // number of iterations
    parallelism: 1,
  });

  return hash;
}

// Appends the same pepper then verifies against stored hash
async function verifyPassword(plainPassword, storedHash) {
  const pepperedPassword = plainPassword + PEPPER;

  const isValid = await argon2.verify(storedHash, pepperedPassword);
  return isValid;
}

module.exports = { hashPassword, verifyPassword, validatePasswordStrength };