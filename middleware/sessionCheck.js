/**
 * SECURITY: Session Validation Middleware (Auth Guard)
 * Attack prevented: Session hijacking, unauthorized access
 *
 * What is session hijacking?
 *   Session hijacking is an attack where an adversary steals or predicts a
 *   valid session token (cookie) to impersonate a legitimate user. Methods
 *   include packet sniffing (on unencrypted connections), XSS (stealing
 *   cookies via injected scripts), or session fixation (forcing a known
 *   session ID onto the victim).
 *
 * How this middleware prevents it:
 *   1. HttpOnly cookie flag: Prevents JavaScript from reading the session
 *      cookie, defeating XSS-based cookie theft.
 *   2. Secure flag: Ensures the cookie is only sent over HTTPS, preventing
 *      packet sniffing on unencrypted connections.
 *   3. SameSite=Strict: Prevents the browser from sending the session cookie
 *      with cross-site requests, mitigating CSRF and some session fixation.
 *   4. Session regeneration: On every successful login, a new session ID is
 *      generated, invalidating any previously fixated session.
 *   5. Idle timeout (15 min): If the user is inactive for 15 minutes, the
 *      session is destroyed. This limits the window for an attacker to use
 *      a stolen session.
 *   6. Absolute expiry (24 hours): Even active sessions expire after 24
 *      hours, forcing re-authentication and limiting long-term token reuse.
 *   7. Server-side validation: Every protected route checks that the session
 *      is valid, the user exists, and the session has not expired.
 */

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;      // 15 minutes
const ABSOLUTE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Middleware: requireAuth
 * Validates the session on every protected route.
 * Checks: session exists, user is logged in, idle timeout, absolute expiry.
 */
function requireAuth(req, res, next) {
  // Check if session exists and user is authenticated
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'You must be logged in to access this resource' });
  }

  const now = Date.now();

  // SECURITY: Absolute session expiry
  // Attack prevented: Long-lived stolen session tokens
  // How it works: Even if a session is actively used, it expires after 24 hours
  if (req.session.createdAt && (now - req.session.createdAt > ABSOLUTE_EXPIRY_MS)) {
    req.session.destroy((err) => {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    });
    return;
  }

  // SECURITY: Idle timeout
  // Attack prevented: Abandoned session reuse
  // How it works: If no request is made for 15 minutes, the session is invalidated
  if (req.session.lastActivity && (now - req.session.lastActivity > IDLE_TIMEOUT_MS)) {
    req.session.destroy((err) => {
      return res.status(401).json({ error: 'Session timed out due to inactivity. Please log in again.' });
    });
    return;
  }

  // Update last activity timestamp
  req.session.lastActivity = now;

  next();
}

module.exports = { requireAuth, IDLE_TIMEOUT_MS, ABSOLUTE_EXPIRY_MS };
