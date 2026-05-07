/*
 * SECURITY: TOTP Two-Factor Authentication
 * Attack prevented: Account takeover when a password is compromised
 *
 * TOTP (Time-based One-Time Password, RFC 6238) works by having the
 * server and the user's authenticator app share a secret key. Both
 * sides combine that secret with the current time (in 30-second steps)
 * to independently produce the same 6-digit code. The code changes
 * every 30 seconds, so it's only valid for a short window.
 *
 * The point is that even if someone gets hold of a user's password,
 * they still can't log in without the code from the physical device.
 * Phishing, credential stuffing, keyloggers — none of those are
 * enough on their own when 2FA is enabled.
 *
 * Library: otplib (v12) — RFC-compliant, works with Google Authenticator/Authy.
 * QR codes generated with the qrcode package.
 */

const { authenticator } = require('otplib');
const QRCode = require('qrcode');

// Create a fresh base32 secret for a new user
function generateTOTPSecret() {
  return authenticator.generateSecret();
}

// Build a QR code data URL so the user can scan the secret into their app
async function generateQRCode(username, secret) {
  const otpauthUrl = authenticator.keyuri(username, 'TheSurvivorNetwork', secret);
  return QRCode.toDataURL(otpauthUrl);
}

// Check if a 6-digit code matches the expected value for this secret
function verifyTOTP(token, secret) {
  try {
    return authenticator.verify({ token, secret });
  } catch (err) {
    return false;
  }
}

module.exports = { generateTOTPSecret, generateQRCode, verifyTOTP };
