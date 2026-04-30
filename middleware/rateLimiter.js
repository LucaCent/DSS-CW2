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
 * Library: express-rate-limit v7
 */

const rateLimit = require('express-rate-limit');

// Global limiter — 100 requests per 15 min per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter limiter for auth routes — 10 attempts per 15 min per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many authentication attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { generalLimiter, authLimiter };
