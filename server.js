/*
 * Entry point — wires middleware, routes, and security layers.
 * Order matters here: helmet first, then parsing, then sessions,
 * then CSRF, then the actual routes.
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

/*
 * SECURITY: HTTP Security Headers (helmet.js)
 * Attack prevented: Clickjacking, MIME sniffing, protocol downgrade, XSS
 *
 * helmet sets a bunch of headers in one go:
 *   - X-Frame-Options: DENY — stops the page being loaded in an iframe
 *     (clickjacking). CSP frame-ancestors: 'none' does the same thing
 *     for modern browsers; both are set for compatibility.
 *   - X-Content-Type-Options: nosniff — stops browsers guessing MIME types
 *   - HSTS — forces HTTPS for a year, prevents protocol downgrades
 *   - Referrer-Policy: same-origin — doesn't leak URLs to other sites
 *   - Permissions-Policy — turns off camera/mic/geo since we don't need them
 *   - CSP: scripts only from 'self', so injected inline scripts are blocked
 *
 * Library: helmet v7
 */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
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

// General Rate Limiting
app.use(generalLimiter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Static Files
app.use(express.static(path.join(__dirname, 'public')));

/*
 * SECURITY: Session Cookie Configuration
 * Attack prevented: Session hijacking, session fixation
 *
 * Cookie flags that matter:
 *   HttpOnly  — JS can't read the cookie, so XSS can't steal it
 *   Secure    — cookie only sent over HTTPS (disabled for localhost)
 *   SameSite  — 'strict' means the browser won't attach it to cross-site
 *               requests, which blocks CSRF and cross-origin session leaks
 *   maxAge    — 24h hard limit; stolen tokens expire after a day
 *
 * Sessions are stored in Postgres (connect-pg-simple) instead of memory
 * so they survive restarts and can be properly invalidated.
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

app.use(validateCSRF);
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

// Routes
app.use('/auth', require('./routes/auth'));
app.use('/posts', require('./routes/posts'));
app.use('/password-reset', require('./routes/passwordReset'));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// SECURITY: Generic errors only — never leak stack traces or DB details to the client
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

// Catch unhandled async errors so the process doesn't crash
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  logger.security('Unhandled promise rejection', { reason: String(reason) });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Secure Blog server running at http://localhost:${PORT}`);
  logger.info(`Server started on port ${PORT}`);
});