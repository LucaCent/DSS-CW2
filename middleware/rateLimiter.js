/**
 * SECURITY: Rate Limiter Middleware
 * Attack prevented: Brute force attacks, denial of service, account enumeration
 *
 * How it works:
 *   - Uses express-rate-limit to restrict the number of requests from a
 *     single IP address within a time window.
 *   - A stricter limiter is applied to authentication routes (login,
 *     register) to prevent brute-force password guessing.
 *   - A general limiter is applied globally to prevent DoS attacks.
 *   - Combined with application-level account lockout (exponential backoff
 *     after 5 failed login attempts) for defence in depth.
 *
 * Library used: express-rate-limit (v7.x) — a well-maintained, widely used
 *   rate limiting middleware for Express.js.
 */

const rateLimit = require('express-rate-limit');

/**
 * SECURITY: General Rate Limiter
 * Attack prevented: Denial of service (DoS)
 * How it works: Limits each IP to 100 requests per 15-minute window.
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * SECURITY: Auth Route Rate Limiter (Strict)
 * Attack prevented: Brute force login attacks, credential stuffing
 * How it works: Limits each IP to 10 login/register attempts per 15-minute
 *   window. This is layered on top of per-account lockout for defence in depth.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many authentication attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { generalLimiter, authLimiter };
