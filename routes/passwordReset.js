/**
 * SECURITY: Password Reset Routes
 * Attack prevented: Account takeover via insecure password reset
 *
 * How the secure password reset flow works:
 *   1. User requests a reset by providing their username.
 *   2. Server generates a cryptographically random one-time token.
 *   3. Only the SHA-256 hash of the token is stored in the database.
 *      The plaintext token is returned to the user (in a real app, this
 *      would be sent via email; here we display it for demo purposes).
 *   4. The token expires after 15 minutes.
 *   5. When the user submits the token + new password, the server hashes
 *      the submitted token and compares it against the stored hash.
 *   6. If valid and not expired, the password is updated and the token
 *      is marked as used.
 *
 * Why hash the token in the DB?
 *   If an attacker gains read access to the database, they see only
 *   hashed tokens and cannot use them to reset anyone's password.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const pool = require('../db/pool');
const { hashToken } = require('../utils/crypto');
const { validatePassword, validateLength } = require('../utils/sanitise');
const logger = require('../utils/logger');

const BCRYPT_ROUNDS = 12;
const TOKEN_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Apply pepper to a password before hashing.
 */
function applyPepper(password) {
  return password + process.env.PEPPER;
}

// ─────────────────────────────────────────────────────────────
// POST /password-reset/request — Request a password reset
// ─────────────────────────────────────────────────────────────
router.post('/request', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const usernameCheck = validateLength('username', username);
    if (!usernameCheck.valid) return res.status(400).json({ error: usernameCheck.message });

    // SECURITY: SQL Injection Prevention — parameterised query
    const result = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    // SECURITY: Account enumeration prevention
    // Always return success message regardless of whether user exists
    if (result.rows.length === 0) {
      return res.json({
        message: 'If an account with that username exists, a reset token has been generated.',
      });
    }

    const userId = result.rows[0].id;

    // Invalidate any existing unused tokens for this user
    await pool.query(
      'UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE',
      [userId]
    );

    // Generate a cryptographically random token
    const plainToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(plainToken);
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRY_MS);

    // Store only the hash in the database
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, tokenHash, expiresAt]
    );

    logger.info('Password reset requested', { username, ip: req.ip });

    // In a real application, the token would be sent via email.
    // For this demo, we return it directly.
    res.json({
      message: 'If an account with that username exists, a reset token has been generated.',
      resetToken: plainToken, // Would be emailed in production
      expiresIn: '15 minutes',
    });
  } catch (err) {
    console.error('Password reset request error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /password-reset/confirm — Confirm password reset with token
// ─────────────────────────────────────────────────────────────
router.post('/confirm', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    const passwordCheck = validatePassword(newPassword);
    if (!passwordCheck.valid) return res.status(400).json({ error: passwordCheck.message });

    // Hash the submitted token to compare with stored hash
    const tokenHash = hashToken(token);

    // SECURITY: SQL Injection Prevention — parameterised query
    const result = await pool.query(
      `SELECT id, user_id, expires_at, used FROM password_reset_tokens
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      logger.security('Invalid password reset token', { ip: req.ip });
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const resetRecord = result.rows[0];

    if (resetRecord.used) {
      return res.status(400).json({ error: 'This reset token has already been used' });
    }

    if (new Date(resetRecord.expires_at) < new Date()) {
      return res.status(400).json({ error: 'This reset token has expired. Please request a new one.' });
    }

    // Hash the new password with pepper
    const pepperedPassword = applyPepper(newPassword);
    const passwordHash = await bcrypt.hash(pepperedPassword, BCRYPT_ROUNDS);

    // Update password and mark token as used
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, resetRecord.user_id]);
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [resetRecord.id]);

    // Reset failed login attempts
    await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [resetRecord.user_id]);

    logger.info('Password reset completed', { userId: resetRecord.user_id, ip: req.ip });

    res.json({ message: 'Password has been reset successfully. You can now log in with your new password.' });
  } catch (err) {
    console.error('Password reset confirm error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

module.exports = router;
