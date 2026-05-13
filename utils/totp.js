/*
 * TOTP (Time-based One-Time Password, RFC 6238) — how authenticator apps work.
 * The server and the user's app share a secret key. Both sides independently
 * combine that key with the current 30-second time window to generate the same
 * 6-digit code. No network call needed at login; the code just rotates every 30s.
 *
 * Even with a stolen password, an attacker needs the physical device to log in.
 * Credential stuffing and keyloggers don't help if 2FA is on.
 *
 * otplib handles the RFC details; qrcode generates the scan-able QR so users
 * don't have to type a base32 string into their authenticator app by hand.
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
