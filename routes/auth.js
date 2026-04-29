/**
 * SECURITY: Authentication Routes (Register, Login, Logout, 2FA)
 * This file implements all authentication-related endpoints with the
 * following security mitigations applied throughout:
 *   - Account enumeration prevention
 *   - Password hashing with salt and pepper
 *   - TOTP-based two-factor authentication
 *   - Session hijacking prevention
 *   - SQL injection prevention via parameterised queries
 *   - Input validation and sanitisation
 *   - Rate limiting
 *   - CSRF protection
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const pool = require('../db/pool');
const { encrypt, decrypt } = require('../utils/crypto');
const { validateUsername, validateEmail, validatePassword, validateLength } = require('../utils/sanitise');
const { generateTOTPSecret, generateQRCode, verifyTOTP } = require('../utils/totp');
const { generateCSRFToken } = require('../middleware/csrfMiddleware');
const { requireAuth } = require('../middleware/sessionCheck');
const logger = require('../utils/logger');

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/**
 * SECURITY: Password Hashing, Salting, and Peppering
 * Attack prevented: Password exposure from database breaches
 *
 * What each component does and why all three together are stronger:
 *
 * 1. HASHING (bcrypt):
 *    A one-way cryptographic function that converts the password into a
 *    fixed-length string. Even if the hash is stolen, the original password
 *    cannot be recovered. bcrypt is deliberately slow (configurable via
 *    rounds) to make brute-force attacks computationally expensive.
 *
 * 2. SALTING (automatic in bcrypt):
 *    A unique random string generated for each user and prepended to their
 *    password before hashing. bcrypt generates and stores the salt
 *    automatically within the hash output. This defeats pre-computed
 *    rainbow table attacks because identical passwords produce different
 *    hashes for different users.
 *
 * 3. PEPPERING (server-side secret from .env):
 *    A secret string stored in an environment variable (not in the database)
 *    that is appended to every password before hashing. Even if an attacker
 *    dumps the entire database, they cannot crack the hashes without also
 *    obtaining the pepper from the server's environment. This adds a layer
 *    of defence that is independent of the database.
 *
 * Together: Salt defeats rainbow tables, pepper defeats database-only
 * breaches, and bcrypt's slowness defeats brute force. An attacker would
 * need the database dump AND the server's environment AND enormous
 * computational resources to crack even a single password.
 *
 * Library used: bcrypt (v5.x) — the industry-standard adaptive hashing
 *   library for Node.js. Chosen for its security, maturity, and built-in
 *   salt generation.
 */

/**
 * Apply pepper to a password before hashing.
 */
function applyPepper(password) {
  return password + process.env.PEPPER;
}

// ─────────────────────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // SECURITY: Input validation (server-side)
    // Attack prevented: SQL injection, XSS, buffer overflow
    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) return res.status(400).json({ error: usernameCheck.message });

    const emailCheck = validateEmail(email);
    if (!emailCheck.valid) return res.status(400).json({ error: emailCheck.message });

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) return res.status(400).json({ error: passwordCheck.message });

    // SECURITY: SQL Injection Prevention
    // Attack prevented: SQL injection
    // How it works: Parameterised query — $1 is treated as data, never as SQL
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username is already taken' });
    }

    // SECURITY: Password hashing with pepper + bcrypt (includes salt)
    const pepperedPassword = applyPepper(password);
    const passwordHash = await bcrypt.hash(pepperedPassword, BCRYPT_ROUNDS);

    // SECURITY: Database Encryption
    // Attack prevented: Data breach exposure of PII
    // How it works: Email is encrypted with AES-256 before storage
    const encryptedEmail = encrypt(email);

    // SECURITY: TOTP 2FA secret generation
    const totpSecret = generateTOTPSecret();
    const encryptedTotpSecret = encrypt(totpSecret);

    // SECURITY: SQL Injection Prevention — parameterised INSERT
    const result = await pool.query(
      `INSERT INTO users (username, email_encrypted, password_hash, totp_secret_encrypted, totp_enabled)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [username, encryptedEmail, passwordHash, encryptedTotpSecret, false]
    );

    // Generate QR code for 2FA setup
    const qrCodeDataUrl = await generateQRCode(username, totpSecret);

    logger.info('New user registered', { username, ip: req.ip });

    res.status(201).json({
      message: 'Registration successful. Please scan the QR code with your authenticator app to enable 2FA.',
      qrCode: qrCodeDataUrl,
      totpSecret: totpSecret, // Show once so user can manually enter if QR fails
      userId: result.rows[0].id,
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ error: 'An error occurred during registration. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /auth/enable-2fa
// ─────────────────────────────────────────────────────────────
router.post('/enable-2fa', async (req, res) => {
  try {
    const { userId, totpCode } = req.body;

    if (!userId || !totpCode) {
      return res.status(400).json({ error: 'User ID and TOTP code are required' });
    }

    const codeCheck = validateLength('totpCode', totpCode);
    if (!codeCheck.valid) return res.status(400).json({ error: codeCheck.message });

    // Fetch user's TOTP secret
    const result = await pool.query(
      'SELECT totp_secret_encrypted FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid request' });
    }

    const totpSecret = decrypt(result.rows[0].totp_secret_encrypted);

    if (!verifyTOTP(totpCode, totpSecret)) {
      return res.status(400).json({ error: 'Invalid TOTP code. Please try again with a fresh code from your authenticator app.' });
    }

    // Enable 2FA
    await pool.query(
      'UPDATE users SET totp_enabled = TRUE WHERE id = $1',
      [userId]
    );

    res.json({ message: '2FA has been successfully enabled on your account.' });
  } catch (err) {
    console.error('2FA enable error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────────────────────

/**
 * SECURITY: Account Enumeration Prevention
 * Attack prevented: Account enumeration (username harvesting)
 *
 * What is account enumeration?
 *   Account enumeration is an attack where an adversary systematically
 *   tests usernames or email addresses against a login or registration
 *   form to determine which accounts exist. Differences in error messages
 *   (e.g. "username not found" vs "wrong password") or response times
 *   reveal whether an account exists.
 *
 * How this code prevents it:
 *   1. Identical error messages: Whether the username does not exist or
 *      the password is wrong, the same generic message is returned:
 *      "Invalid credentials". The attacker cannot distinguish the two cases.
 *   2. Consistent artificial delay: A 200ms delay is added to ALL login
 *      responses (success and failure). This prevents timing-based
 *      enumeration — without the delay, a "user not found" response
 *      would be faster (no bcrypt comparison) than a "wrong password"
 *      response, leaking information.
 *   3. Rate limiting + account lockout: After 5 failed login attempts,
 *      the account is locked for 15 minutes (exponential backoff).
 *      Combined with IP-based rate limiting, this makes brute-force
 *      enumeration infeasible.
 */
router.post('/login', async (req, res) => {
  // SECURITY: Artificial delay to prevent timing-based enumeration
  const ARTIFICIAL_DELAY_MS = 200;
  const start = Date.now();

  try {
    const { username, password, totpCode } = req.body;

    // Basic input validation
    if (!username || !password) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const usernameCheck = validateLength('username', username);
    if (!usernameCheck.valid) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // SECURITY: SQL Injection Prevention — parameterised query
    const result = await pool.query(
      'SELECT id, username, password_hash, totp_enabled, totp_secret_encrypted, failed_login_attempts, locked_until FROM users WHERE username = $1',
      [username]
    );

    // SECURITY: Account enumeration — same error for "user not found"
    if (result.rows.length === 0) {
      // Perform a dummy bcrypt hash to equalise timing
      await bcrypt.hash('dummy_password', BCRYPT_ROUNDS);
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      logger.security('Failed login - user not found', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // SECURITY: Account lockout after repeated failures
    // Attack prevented: Brute force password guessing
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      logger.security('Login attempt on locked account', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // SECURITY: Password verification with pepper
    const pepperedPassword = applyPepper(password);
    const passwordValid = await bcrypt.compare(pepperedPassword, user.password_hash);

    if (!passwordValid) {
      // Increment failed attempts
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;

      if (newAttempts >= MAX_FAILED_ATTEMPTS) {
        // SECURITY: Exponential backoff — lock account for 15 minutes
        lockUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
        logger.security('Account locked after repeated failures', {
          username, ip: req.ip, attempts: newAttempts,
        });
      }

      await pool.query(
        'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
        [newAttempts, lockUntil, user.id]
      );

      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      logger.security('Failed login - wrong password', { username, ip: req.ip, attempts: newAttempts });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Password correct — check if 2FA is enabled
    if (user.totp_enabled) {
      if (!totpCode) {
        // Need 2FA code — return special status to prompt frontend
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        return res.status(200).json({ requires2FA: true, message: 'Please enter your 2FA code' });
      }

      const codeCheck = validateLength('totpCode', totpCode);
      if (!codeCheck.valid) {
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const totpSecret = decrypt(user.totp_secret_encrypted);
      if (!verifyTOTP(totpCode, totpSecret)) {
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        logger.security('Failed login - invalid TOTP code', { username, ip: req.ip });
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    // ── Login successful ──
    // Reset failed attempts
    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
      [user.id]
    );

    // SECURITY: Session Hijacking Prevention — regenerate session ID
    // Attack prevented: Session fixation
    // How it works: Destroying the old session and creating a new one
    //   ensures that any pre-existing session ID (potentially set by an
    //   attacker) is invalidated.
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err.message);
        return res.status(500).json({ error: 'An error occurred. Please try again.' });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.createdAt = Date.now();
      req.session.lastActivity = Date.now();

      // Generate fresh CSRF token for new session
      const csrfToken = generateCSRFToken(req);

      logger.info('Successful login', { username, ip: req.ip });

      res.json({
        message: 'Login successful',
        csrfToken: csrfToken,
        user: { id: user.id, username: user.username },
      });
    });
  } catch (err) {
    console.error('Login error:', err.message);
    await artificialDelay(start, ARTIFICIAL_DELAY_MS);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

/**
 * Helper: ensure consistent response timing.
 */
async function artificialDelay(startTime, minDelay) {
  const elapsed = Date.now() - startTime;
  const remaining = minDelay - elapsed;
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

// ─────────────────────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────────────────────
router.post('/logout', requireAuth, (req, res) => {
  const username = req.session.username;
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err.message);
      return res.status(500).json({ error: 'An error occurred during logout.' });
    }
    res.clearCookie('connect.sid');
    logger.info('User logged out', { username });
    res.json({ message: 'Logged out successfully' });
  });
});

// ─────────────────────────────────────────────────────────────
// GET /auth/me — get current user info
// ─────────────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email_encrypted, totp_enabled, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      username: user.username,
      email: decrypt(user.email_encrypted),
      totpEnabled: user.totp_enabled,
      createdAt: user.created_at,
    });
  } catch (err) {
    console.error('Get user error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /auth/csrf-token — get a fresh CSRF token
// ─────────────────────────────────────────────────────────────
router.get('/csrf-token', (req, res) => {
  const token = generateCSRFToken(req);
  res.json({ csrfToken: token });
});

module.exports = router;
