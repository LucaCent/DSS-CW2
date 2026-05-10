/*
 * CSRF — when attacker.com tricks the user's browser into making a request
 * to our app. The browser sends the session cookie automatically, so without
 * extra protection the server has no way to tell the request didn't come from
 * our own frontend.
 *
 * Fix: generate a 32-byte random token, store it in the session, require it
 * on every POST/PUT/DELETE. A cross-origin page can't read our token (same-
 * origin policy), so a forged request will always be missing or wrong.
 * SameSite=strict on the cookie is an extra layer on top of this.
 *
 * Comparison uses timingSafeEqual so an attacker can't brute-force the token
 * one byte at a time by measuring response times.
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

  // Token verified — rotate it so the same token can't be replayed on the
  // next request. Client should read X-New-CSRF-Token from every response
  // and replace its stored copy.
  const rotated = generateCSRFToken(req);
  res.setHeader('X-New-CSRF-Token', rotated);

  next();
}

module.exports = { generateCSRFToken, validateCSRF };
