/*
 * Entry point — wires middleware, routes, and security layers.
 * Order matters here: helmet first, then parsing, then sessions,
 * then CSRF, then the actual routes.
 */

require('dotenv').config();
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
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
      // 'unsafe-inline' removed from scriptSrc — all JS is in /js/app.js (external).
      // This blocks injected <script> blocks, which is the primary XSS vector.
      // scriptSrcAttr still needs 'unsafe-inline' for onclick/onsubmit attributes
      // in the current HTML; eliminating those would require a full frontend refactor
      // to use addEventListener() instead.
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'unsafe-inline'"],
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

/*
 * SECURITY: Request ID Middleware
 * Attack prevented: Information disclosure during incident response
 * A unique opaque ID is attached to every request. Error responses
 * return only this ID — no stack traces, no file paths, no library
 * versions. The same ID is logged server-side with the full error,
 * so developers can correlate a user-reported error to the exact
 * log entry without exposing any internal detail to an attacker.
 */
app.use((req, res, next) => {
  req.id = crypto.randomBytes(6).toString('hex');
  next();
});

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
    secure: fs.existsSync('key.pem'), // true when TLS certs are present
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

/*
 * SECURITY: Global Error Handler — Stack Trace / Information Disclosure Prevention
 * Attack prevented: OWASP A05:2021 — Security Misconfiguration (information leakage)
 *
 * Without this, Express's default error handler sends the full stack trace,
 * file paths, library version numbers, and sometimes DB column names back
 * to the client. All of that is free reconnaissance for an attacker.
 *
 * What the client sees: a generic message + an opaque requestId.
 * What the server logs: the full stack trace tagged with the same requestId,
 * so a developer can look up exactly what went wrong from a user report.
 *
 * Known client-error types are mapped to safe 4xx responses so the
 * user gets something actionable without leaking internals.
 *
 * Must be the LAST middleware registered (after all routes) and must
 * have exactly four parameters (err, req, res, next) for Express to
 * treat it as an error handler.
 */
app.use((err, req, res, next) => {
  // Map known client errors to safe, informative 4xx responses
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Everything else is a 500 — log full detail server-side only
  const requestId = req.id || crypto.randomBytes(6).toString('hex');
  logger.security(`[${requestId}] Unhandled application error`, {
    ip: req.ip,
    method: req.method,
    path: req.path,
    error: err.message,
    stack: err.stack,
  });

  res.status(500).json({
    error: 'An internal error occurred',
    requestId,
  });
});

// Catch unhandled async errors so the process doesn't crash
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  logger.security('Unhandled promise rejection', { reason: String(reason) });
});

// Start Server — HTTPS if certs exist, HTTP otherwise
const PORT = process.env.PORT || 3000;

try {
  const httpsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
  };
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`The Survivor Network running at https://localhost:${PORT}`);
    logger.info(`Server started (HTTPS) on port ${PORT}`);
  });
} catch (err) {
  // Certs not found — fall back to plain HTTP for local development.
  // Generate with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
  http.createServer(app).listen(PORT, () => {
    console.log(`The Survivor Network running at http://localhost:${PORT} (no TLS certs found)`);
    logger.info(`Server started (HTTP fallback) on port ${PORT}`);
  });
}