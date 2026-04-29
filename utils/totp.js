/**
 * SECURITY: TOTP-Based Two-Factor Authentication (2FA)
 * Attack prevented: Account takeover via stolen passwords
 *
 * What is TOTP?
 *   Time-based One-Time Password (TOTP) is a 2FA method defined in RFC 6238.
 *   It generates a 6-digit code that changes every 30 seconds, based on a
 *   shared secret and the current time. The user stores the secret in an
 *   authenticator app (e.g. Google Authenticator, Authy), and the server
 *   stores an encrypted copy.
 *
 * How time-based codes work:
 *   1. A shared secret is generated during registration and stored by both
 *      the server (encrypted) and the user's authenticator app (via QR code).
 *   2. Every 30 seconds, both sides independently compute HMAC-SHA1 over
 *      the secret + current time step, then truncate to a 6-digit number.
 *   3. When the user logs in, they enter the current 6-digit code.
 *   4. The server computes the expected code and checks it matches, with
 *      a small time window tolerance (±1 step) to account for clock drift.
 *
 * What attack this defeats:
 *   Even if an attacker steals the user's password (via phishing, data
 *   breach, or keylogger), they cannot log in without also having physical
 *   access to the user's authenticator device. This makes credential-only
 *   attacks insufficient for account compromise.
 *
 * Library used: otplib (v12.0.1) — a well-maintained, RFC-compliant TOTP
 *   library for Node.js. Chosen for its simplicity and correctness.
 */

const { authenticator } = require('otplib');
const QRCode = require('qrcode');

/**
 * Generate a new TOTP secret for a user.
 * Returns the base32-encoded secret string.
 */
function generateTOTPSecret() {
  return authenticator.generateSecret();
}

/**
 * Generate a QR code data URL for the user to scan with their authenticator app.
 * @param {string} username - The user's username (shown in the app)
 * @param {string} secret - The base32-encoded TOTP secret
 * @returns {Promise<string>} Data URL of the QR code image
 */
async function generateQRCode(username, secret) {
  const otpauthUrl = authenticator.keyuri(username, 'SecureBlog', secret);
  return QRCode.toDataURL(otpauthUrl);
}

/**
 * Verify a 6-digit TOTP code against the stored secret.
 * @param {string} token - The 6-digit code entered by the user
 * @param {string} secret - The base32-encoded TOTP secret
 * @returns {boolean} True if the code is valid
 */
function verifyTOTP(token, secret) {
  try {
    return authenticator.verify({ token, secret });
  } catch (err) {
    return false;
  }
}

module.exports = { generateTOTPSecret, generateQRCode, verifyTOTP };
