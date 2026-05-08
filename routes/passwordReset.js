/*
 * Password reset routes.
 * Flow: request → generate random token → store only the SHA-256 hash in
 * the DB (not the token itself) → return plaintext token to user (would
 * be emailed in production) → on confirm, re-hash submitted token and
 * compare. 15-minute expiry, single-use, and requesting a new token
 * invalidates any outstanding ones.
 *
 * Storing the hash means a DB dump doesn't hand an attacker working reset
 * links — same reasoning as not storing plaintext passwords.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { hashPassword } = require('../utils/hashing');
const pool = require('../db/pool');
const { hashToken } = require('../utils/crypto');
const { validatePassword, validateLength } = require('../utils/sanitise');
const logger = require('../utils/logger');

const TOKEN_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

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

    const result = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    // Same message whether user exists or not — prevents enumeration
    if (result.rows.length === 0) {
      return res.json({
        message: 'If an account with that username exists, a reset token has been generated.',
      });
    }

    const userId = result.rows[0].id;

    // Kill any old unused tokens first
    await pool.query(
      'UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE',
      [userId]
    );

    const plainToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(plainToken);
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRY_MS);

    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, tokenHash, expiresAt]
    );

    logger.info('Password reset requested', { username, ip: req.ip });

    // TODO: send this via email instead of returning it in the response
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

    const tokenHash = hashToken(token);

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

    const passwordHash = await hashPassword(newPassword);

    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, resetRecord.user_id]);
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [resetRecord.id]);
    await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [resetRecord.user_id]);

    logger.info('Password reset completed', { userId: resetRecord.user_id, ip: req.ip });

    res.json({ message: 'Password has been reset successfully. You can now log in with your new password.' });
  } catch (err) {
    console.error('Password reset confirm error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

module.exports = router;
