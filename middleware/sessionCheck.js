/*
 * SECURITY: Session Hijacking Prevention — Auth Guard Middleware
 * Attack prevented: Session hijacking, session fixation, unauthorised access
 *
 * Session hijacking is where someone steals or guesses a user's session
 * cookie and uses it to impersonate them. Common vectors:
 *   - XSS scripts reading document.cookie  → blocked by HttpOnly flag
 *   - Sniffing unencrypted traffic         → blocked by Secure flag (HTTPS)
 *   - Cross-site request tricks            → blocked by SameSite=Strict
 *   - Pre-setting a known session ID       → blocked by regenerating the
 *                                             session on login
 *
 * This middleware also enforces two timeouts:
 *   - 15 min idle timeout — if the user walks away, the session dies
 *   - 24 hour absolute expiry — forces re-auth even for active sessions
 *
 * Cookie flags are set in server.js; this file handles the timeout checks
 * and makes sure every protected route actually has a valid session.
 */

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;      // 15 minutes
const ABSOLUTE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'You must be logged in to access this resource' });
  }

  const now = Date.now();

  // Hard cap at 24 hours regardless of activity
  if (req.session.createdAt && (now - req.session.createdAt > ABSOLUTE_EXPIRY_MS)) {
    req.session.destroy((err) => {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    });
    return;
  }

  // No activity for 15 min → session is dead
  if (req.session.lastActivity && (now - req.session.lastActivity > IDLE_TIMEOUT_MS)) {
    req.session.destroy((err) => {
      return res.status(401).json({ error: 'Session timed out due to inactivity. Please log in again.' });
    });
    return;
  }

  req.session.lastActivity = now;

  next();
}

module.exports = { requireAuth, IDLE_TIMEOUT_MS, ABSOLUTE_EXPIRY_MS };
