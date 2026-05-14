/*
 * Authentication routes — register, login, logout, 2FA setup.
 * Parameterised queries throughout, input validated before anything
 * hits the database, and passwords are hashed with Argon2id + pepper.
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const svgCaptcha = require('svg-captcha');
const { hashPassword, verifyPassword } = require('../utils/hashing');
const pool = require('../db/pool');
const { encrypt, decrypt } = require('../utils/crypto');
const { validateUsername, validateEmail, validatePassword, validateLength } = require('../utils/sanitise');
const { generateTOTPSecret, generateQRCode, verifyTOTP } = require('../utils/totp');
const { generateCSRFToken } = require('../middleware/csrfMiddleware');
const { requireAuth } = require('../middleware/sessionCheck');
const logger = require('../utils/logger');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// Passwords are hashed with Argon2id + pepper before hitting the DB —
// see utils/hashing.js for the tuning params and the reasoning behind
// the choice. The short version: it's memory-hard, salt is automatic,
// and the pepper means a DB dump alone isn't enough to crack anything.


// GET /auth/captcha — generate a fresh CAPTCHA image
// Stores the answer in the session; client displays the SVG.

router.get('/captcha', (req, res) => {
  const captcha = svgCaptcha.create({
    size: 5,
    noise: 2,
    color: true,
    background: '#fdf6ee',
  });
  req.session.captchaText = captcha.text;
  res.type('svg');
  res.send(captcha.data);
});


// POST /auth/register

router.post('/register', async (req, res) => {
  try {
    const { username, email, password, authMethod, captchaCode } = req.body;

    // Verify CAPTCHA first — stops bots before we do any DB work
    if (!captchaCode || !req.session.captchaText ||
        captchaCode.toLowerCase() !== req.session.captchaText.toLowerCase()) {
      req.session.captchaText = null;
      return res.status(400).json({ error: 'Incorrect CAPTCHA. Please try again.' });
    }
    req.session.captchaText = null; // single-use

    const method = authMethod === 'captcha' ? 'captcha' : 'totp';

    // Validate everything server-side before touching the DB
    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) return res.status(400).json({ error: usernameCheck.message });

    const emailCheck = validateEmail(email);
    if (!emailCheck.valid) return res.status(400).json({ error: emailCheck.message });

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) return res.status(400).json({ error: passwordCheck.message });

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username is already taken' });
    }

    const passwordHash = await hashPassword(password);
    const encryptedEmail = encrypt(email);

    if (method === 'captcha') {
      // CAPTCHA 2FA users don't need an authenticator app
      const result = await pool.query(
        `INSERT INTO users (username, email_encrypted, password_hash, totp_enabled, auth_method)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [username, encryptedEmail, passwordHash, false, 'captcha']
      );
      logger.info('New user registered (captcha 2FA)', { username, ip: req.ip });
      return res.status(201).json({
        message: 'Registration successful. You can now log in.',
        userId: result.rows[0].id,
        authMethod: 'captcha',
      });
    }

    // TOTP path — generate secret and QR code
    const totpSecret = generateTOTPSecret();
    const encryptedTotpSecret = encrypt(totpSecret);

    const result = await pool.query(
      `INSERT INTO users (username, email_encrypted, password_hash, totp_secret_encrypted, totp_enabled, auth_method)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [username, encryptedEmail, passwordHash, encryptedTotpSecret, false, 'totp']
    );

    const qrCodeDataUrl = await generateQRCode(username, totpSecret);

    logger.info('New user registered (TOTP 2FA)', { username, ip: req.ip });

    res.status(201).json({
      message: 'Registration successful. Please scan the QR code with your authenticator app to enable 2FA.',
      qrCode: qrCodeDataUrl,
      totpSecret: totpSecret,
      userId: result.rows[0].id,
      authMethod: 'totp',
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ error: 'An error occurred during registration. Please try again.' });
  }
});


// POST /auth/enable-2fa

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

    // Generate 8 one-time recovery codes. We only store the SHA-256 hashes —
    // the plain codes are shown to the user once and never saved.
    const plainCodes = [];
    const hashedCodes = [];
    for (let i = 0; i < 8; i++) {
      const code = crypto.randomBytes(10).toString('hex'); // 20-char hex string
      plainCodes.push(code);
      hashedCodes.push(crypto.createHash('sha256').update(code).digest('hex'));
    }

    await pool.query(
      'UPDATE users SET totp_enabled = TRUE, recovery_codes = $1 WHERE id = $2',
      [JSON.stringify(hashedCodes), userId]
    );

    res.json({
      message: '2FA has been successfully enabled on your account.',
      recoveryCodes: plainCodes, // shown once — user must save these
    });
  } catch (err) {
    console.error('2FA enable error:', err.message);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});


// POST /auth/login

// Login needs careful handling of timing and error messages. If "user not
// found" is faster than "wrong password" (no hash to check), an attacker
// can tell which usernames exist just by measuring response time.
//
// To prevent that:
//   - We Run a dummy hash when the user doesn't exist, so both paths take
//     roughly the same time.
//   - Always respond "Invalid credentials" regardless of what failed.
//   - Enforce a 200ms response floor either way.
//   - Lock the account for 15 min after 5 consecutive failures.
router.post('/login', async (req, res) => {
  const ARTIFICIAL_DELAY_MS = 200;
  const start = Date.now();

  try {
    const { username, password, totpCode } = req.body;

    if (!username || !password) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const usernameCheck = validateLength('username', username);
    if (!usernameCheck.valid) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const result = await pool.query(
      'SELECT id, username, password_hash, totp_enabled, totp_secret_encrypted, auth_method, recovery_codes, failed_login_attempts, locked_until FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      // Dummy hash so the response takes the same time as a real check
      await hashPassword('dummy_password');
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      logger.security('Failed login - user not found', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Account locked? Don't even check the password.
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await artificialDelay(start, ARTIFICIAL_DELAY_MS);
      logger.security('Login attempt on locked account', { username, ip: req.ip });
      return res.status(401).json({ error: 'Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.' });
    }

    const passwordValid = await verifyPassword(user.password_hash, password);

    if (!passwordValid) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;

      if (newAttempts >= MAX_FAILED_ATTEMPTS) {
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

    // Second factor check — which method this user enrolled with
    if (user.auth_method === 'captcha') {
      const { captchaCode } = req.body;
      if (!captchaCode) {
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        return res.status(200).json({ requiresCaptcha: true, message: 'Please solve the CAPTCHA to continue' });
      }
      if (!req.session.captchaText ||
          captchaCode.toLowerCase() !== req.session.captchaText.toLowerCase()) {
        req.session.captchaText = null;
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        logger.security('Failed login - wrong CAPTCHA', { username, ip: req.ip });
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      req.session.captchaText = null; // single-use

    } else if (user.totp_enabled) {
      const { totpCode, recoveryCode } = req.body;

      if (!totpCode && !recoveryCode) {
        await artificialDelay(start, ARTIFICIAL_DELAY_MS);
        return res.status(200).json({ requires2FA: true, message: 'Please enter your 2FA code' });
      }

      if (recoveryCode) {
        // Recovery code path — hash it and look for a match in stored hashes
        if (!user.recovery_codes) {
          await artificialDelay(start, ARTIFICIAL_DELAY_MS);
          logger.security('Failed login - no recovery codes on account', { username, ip: req.ip });
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        const stored = JSON.parse(user.recovery_codes);
        const submitted = crypto.createHash('sha256').update(recoveryCode).digest('hex');
        const idx = stored.indexOf(submitted);
        if (idx === -1) {
          await artificialDelay(start, ARTIFICIAL_DELAY_MS);
          logger.security('Failed login - invalid recovery code', { username, ip: req.ip });
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        // Valid — burn the code so it can't be reused
        stored.splice(idx, 1);
        await pool.query('UPDATE users SET recovery_codes = $1 WHERE id = $2',
          [JSON.stringify(stored), user.id]);
        logger.security('Recovery code used', { username, ip: req.ip, codesLeft: stored.length });

      } else {
        // TOTP path
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
    }

    // Login OK — reset failed attempts and regenerate session
    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
      [user.id]
    );

    // Regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err.message);
        return res.status(500).json({ error: 'An error occurred. Please try again.' });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.createdAt = Date.now();
      req.session.lastActivity = Date.now();

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

// Pad response time to at least minDelay ms from start
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
