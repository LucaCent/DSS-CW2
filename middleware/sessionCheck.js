/*
 * Auth guard — attach to any route that needs a logged-in user.
 *
 * Beyond the basic req.session.userId check, it enforces two timeouts:
 *   - 15-min idle: if lastActivity is stale, the session gets destroyed.
 *     Protects against someone walking up to an unattended machine.
 *   - 24-hour absolute: even an active session eventually expires and
 *     forces a fresh login.
 *
 * The cookie flags that prevent the session token being stolen in the
 * first place (HttpOnly, Secure, SameSite) are set in server.js.
 * Session regeneration on login (preventing fixation) is in auth.js.
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

  // No activity for 15 min means session is dead
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
