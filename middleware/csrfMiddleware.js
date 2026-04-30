/*
 * SECURITY: CSRF Protection
 * Attack prevented: Cross-Site Request Forgery
 *
 * CSRF is when a malicious page tricks the user's browser into making a
 * request to our app while the user is logged in — the browser sends the
 * session cookie automatically, so the server thinks it's legitimate.
 *
 * We stop this with a random token that the attacker can't know:
 *   - The server generates a 32-byte random token and stores it in the session.
 *   - The frontend includes it in every POST/PUT/DELETE (as a header or
 *     hidden form field).
 *   - The server checks the submitted token matches the session copy.
 *   - A cross-origin page can't read our token (same-origin policy), so
 *     any forged request will be missing it or have the wrong value.
 *
 * Also using SameSite=Strict on cookies as an extra layer.
 *
 * Custom implementation using Node crypto — no third-party CSRF library.
 */

const crypto = require('crypto');

function generateCSRFToken(req) {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  return token;
}

// Validate token on POST/PUT/DELETE — accepts _csrf body field or x-csrf-token header
function validateCSRF(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const submittedToken = req.body._csrf || req.headers['x-csrf-token'];
  const sessionToken = req.session ? req.session.csrfToken : null;

  if (!submittedToken || !sessionToken) {
    const logger = require('../utils/logger');
    logger.security('CSRF token missing', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      username: req.session ? req.session.username : 'anonymous',
    });
    return res.status(403).json({ error: 'Invalid or missing security token. Please refresh the page and try again.' });
  }

  // Timing-safe compare so an attacker can't figure out the token byte-by-byte
  const tokenBuffer = Buffer.from(submittedToken, 'hex');
  const sessionBuffer = Buffer.from(sessionToken, 'hex');

  if (tokenBuffer.length !== sessionBuffer.length || !crypto.timingSafeEqual(tokenBuffer, sessionBuffer)) {
    const logger = require('../utils/logger');
    logger.security('CSRF token mismatch', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      username: req.session ? req.session.username : 'anonymous',
    });
    return res.status(403).json({ error: 'Invalid security token. Please refresh the page and try again.' });
  }

  next();
}

module.exports = { generateCSRFToken, validateCSRF };
