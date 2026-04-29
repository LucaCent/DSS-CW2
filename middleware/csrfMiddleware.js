/**
 * SECURITY: CSRF (Cross-Site Request Forgery) Protection Middleware
 * Attack prevented: Cross-Site Request Forgery (CSRF)
 *
 * What is CSRF?
 *   CSRF is an attack where a malicious website tricks a user's browser into
 *   making an unwanted request to a different site where the user is already
 *   authenticated. For example, a hidden form on evil.com could submit a POST
 *   request to our blog to delete a post, and the browser would automatically
 *   include the user's session cookie.
 *
 * How token validation prevents CSRF:
 *   1. Token generation: On each session (or page load), the server generates
 *      a cryptographically random, unpredictable CSRF token and stores it in
 *      the user's session.
 *   2. Token embedding: The token is included as a hidden field in every HTML
 *      form and as a header in AJAX requests.
 *   3. Token validation: On every state-changing request (POST, PUT, DELETE),
 *      the server checks that the submitted token matches the one stored in
 *      the session. A cross-origin attacker cannot read the token (due to
 *      same-origin policy), so their forged request will lack the valid token.
 *   4. Defence in depth: Combined with SameSite=Strict cookies, which prevent
 *      the browser from sending cookies with cross-site requests at all.
 *
 * Library used: None (custom implementation using Node.js crypto module).
 *   This avoids dependency on third-party CSRF libraries and gives full
 *   control over the token lifecycle.
 */

const crypto = require('crypto');

/**
 * Generate a cryptographically secure CSRF token and store it in the session.
 */
function generateCSRFToken(req) {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  return token;
}

/**
 * Middleware: validateCSRF
 * Validates the CSRF token on every POST, PUT, and DELETE request.
 * The token can be sent as:
 *   - A hidden form field named '_csrf'
 *   - A request header named 'x-csrf-token'
 */
function validateCSRF(req, res, next) {
  // Only validate state-changing methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const submittedToken = req.body._csrf || req.headers['x-csrf-token'];
  const sessionToken = req.session ? req.session.csrfToken : null;

  if (!submittedToken || !sessionToken) {
    // SECURITY: Log CSRF failure for monitoring
    const logger = require('../utils/logger');
    logger.security('CSRF token missing', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      username: req.session ? req.session.username : 'anonymous',
    });
    return res.status(403).json({ error: 'Invalid or missing security token. Please refresh the page and try again.' });
  }

  // SECURITY: Use timing-safe comparison to prevent timing attacks on token
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
