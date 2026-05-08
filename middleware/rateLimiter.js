/*
 * Two rate limiters: 100 req/15 min site-wide, 10 req/15 min on auth routes.
 * The IP limiter and the per-account lockout in auth.js cover different angles —
 * IP limiter handles distributed floods, account lockout handles a single IP
 * hammering one account's password.
 *
 * Built with a plain Map rather than pulling in express-rate-limit. Each entry
 * is { count, windowStart } keyed by IP. Window resets on expiry; 429 if limit
 * is hit before then.
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
