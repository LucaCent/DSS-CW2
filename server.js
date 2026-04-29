/**
 * ============================================================
 * SECURE BLOG APPLICATION — Entry Point (server.js)
 * ============================================================
 * This file wires together all middleware, routes, and security
 * mitigations. Each middleware layer is applied in a specific
 * order to ensure correct functionality.
 * ============================================================
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const path = require('path');
const pool = require('./db/pool');
const { generalLimiter, authLimiter } = require('./middleware/rateLimiter');
const { validateCSRF } = require('./middleware/csrfMiddleware');
const logger = require('./utils/logger');

const app = express();

// ── 1. Security Headers (helmet.js — must be first) ──────────

/**
 * SECURITY: HTTP Security Headers via helmet.js
 * Attack prevented: Clickjacking, MIME sniffing, protocol downgrade,
 *   information leakage, XSS
 *
 * How it works:
 *   - X-Frame-Options: DENY — prevents the page from being loaded in
 *     an iframe, defeating clickjacking attacks where an attacker overlays
 *     our page with a transparent iframe to trick users into clicking.
 *   - X-Content-Type-Options: nosniff — prevents the browser from MIME
 *     type sniffing, which could allow an attacker to execute a script
 *     disguised as a different content type.
 *   - Strict-Transport-Security — tells the browser to always use HTTPS,
 *     preventing protocol downgrade attacks and cookie hijacking.
 *   - Referrer-Policy: same-origin — prevents the browser from sending
 *     the full URL in the Referer header to external sites, protecting
 *     sensitive URL parameters from leaking.
 *   - Permissions-Policy — disables browser features (camera, microphone,
 *     geolocation) that this application does not need, reducing the
 *     attack surface.
 *
 * Library used: helmet (v7.x) — the standard security header middleware
 *   for Express.js. Sets all recommended headers with one call.
 */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr:["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      /**
       * SECURITY: Clickjacking Protection via CSP frame-ancestors
       * Attack prevented: Clickjacking
       * How it works: The frame-ancestors 'none' directive tells browsers
       *   not to allow this page to be embedded in any frame, iframe, or
       *   object. This is the modern replacement for X-Frame-Options and
       *   is used alongside it for defence in depth.
       */
      frameAncestors: ["'none'"],
    },
  },
  xFrameOptions: { action: 'deny' },
  referrerPolicy: { policy: 'same-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  permissionsPolicy: {
    features: {
      camera: [],
      microphone: [],
      geolocation: [],
    },
  },
}));

// ── 2. General Rate Limiting ──────────────────────────────────
app.use(generalLimiter);

// ── 3. Body Parsing (before CSRF and routes) ──────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ── 4. Static Files ──────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── 5. Session Configuration ──────────────────────────────────

/**
 * SECURITY: Session Hijacking Prevention — Cookie Configuration
 * Attack prevented: Session hijacking, session fixation, CSRF
 *
 * How each flag prevents session hijacking:
 *   - HttpOnly: true — The session cookie cannot be accessed via
 *     client-side JavaScript (document.cookie). This prevents XSS
 *     attacks from stealing the session token.
 *   - Secure: false (set to true in production with HTTPS) — When true,
 *     the cookie is only sent over encrypted HTTPS connections, preventing
 *     an attacker from intercepting it via packet sniffing on the network.
 *   - SameSite: 'strict' — The browser will NOT send this cookie with
 *     any cross-site requests. This prevents CSRF attacks because a
 *     malicious site cannot trigger authenticated requests to our app.
 *     It also mitigates session hijacking via cross-site request tricks.
 *   - maxAge: 24 hours — Absolute session lifetime. Even if a session
 *     token is stolen, it becomes useless after 24 hours.
 *
 * Session store: connect-pg-simple stores sessions in PostgreSQL,
 *   not in server memory. This ensures sessions survive server restarts
 *   and can be properly invalidated.
 */
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    httpOnly: true,
    secure: false,       // Set to true in production with HTTPS
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours absolute expiry
  },
}));

// ── 6. CSRF Protection (after session, before routes) ─────────
app.use(validateCSRF);

// ── 7. Auth Rate Limiter (stricter, only on auth routes) ──────
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

// ── 8. Routes ─────────────────────────────────────────────────
app.use('/auth', require('./routes/auth'));
app.use('/posts', require('./routes/posts'));
app.use('/password-reset', require('./routes/passwordReset'));

// ── 9. SPA fallback — serve index.html for unmatched routes ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── 10. Global Error Handler ──────────────────────────────────

/**
 * SECURITY: Generic Error Responses
 * Attack prevented: Information leakage
 * How it works: The global error handler catches all unhandled errors
 *   and returns a generic message. Stack traces, SQL errors, and other
 *   internal details are NEVER sent to the client — they are only
 *   logged server-side for debugging.
 */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  logger.security('Unhandled application error', {
    ip: req.ip,
    method: req.method,
    path: req.path,
    error: err.message,
  });
  res.status(500).json({ error: 'Something went wrong. Please try again later.' });
});

// ── 11. Unhandled Promise Rejection Handler ───────────────────

/**
 * SECURITY: Graceful crash prevention
 * Attack prevented: Denial of service via unhandled rejections
 * How it works: Catches unhandled promise rejections to prevent the
 *   Node.js process from crashing, which would cause a denial of service.
 */
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  logger.security('Unhandled promise rejection', { reason: String(reason) });
});

// ── Start Server ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Secure Blog server running at http://localhost:${PORT}`);
  logger.info(`Server started on port ${PORT}`);
});