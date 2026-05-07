/*
 * SECURITY: Rate Limiting
 * Attack prevented: Brute force, DoS, automated enumeration
 *
 * Two limiters: a general one (100 req / 15 min per IP) applied to the
 * whole app, and a stricter one (10 req / 15 min per IP) just for login
 * and register. This works alongside the per-account lockout in auth.js
 * so we're covered against both single-IP floods and distributed attacks
 * on a single account.
 *
 * Implemented with a plain JS Map — no third-party library needed.
 * Each entry tracks { count, windowStart } per IP address. When the
 * window expires the counter resets; if max is hit before that, 429.
 */

// Builds an Express middleware that limits each IP to `max` requests
// within a rolling `windowMs` millisecond window.
function createLimiter(windowMs, max, message) {
  // Map<ip, { count: number, windowStart: number }>
  const store = new Map();

  return function rateLimitMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const entry = store.get(ip);

    if (!entry || now - entry.windowStart > windowMs) {
      // First request in this window, or window has expired — reset
      store.set(ip, { count: 1, windowStart: now });
      return next();
    }

    if (entry.count >= max) {
      return res.status(429).json({ error: message });
    }

    entry.count += 1;
    next();
  };
}

// Global limiter — 100 requests per 15 min per IP
const generalLimiter = createLimiter(
  15 * 60 * 1000,
  100,
  'Too many requests. Please try again later.'
);

// Stricter limiter for auth routes — 10 attempts per 15 min per IP
const authLimiter = createLimiter(
  15 * 60 * 1000,
  10,
  'Too many authentication attempts. Please try again later.'
);

module.exports = { generalLimiter, authLimiter };
