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
 * Helmet sets a bunch of security headers in one call — we just tweak
 * a few of its defaults to match what we actually need:
 *
 *   X-Frame-Options: DENY + CSP frame-ancestors: 'none' — both set for
 *   compatibility. Together they stop any site from embedding us in an iframe.
 *
 *   scriptSrc: ['self'] only, no 'unsafe-inline' — injected <script> blocks
 *   go nowhere. scriptSrcAttr still allows inline onclick/onsubmit handlers
 *   because the HTML uses them and refactoring to addEventListener was out of
 *   scope. Worth flagging in the report limitations section.
 *
 *   HSTS maxAge: 1 year — browser remembers to use HTTPS automatically
 *   after the first visit. Permissions-Policy locks out camera/mic/geo.
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

// Every request gets a random 6-byte hex ID attached to req.id.
// Error responses send this back to the client instead of any stack trace
// or internal detail — the user can quote it and we can look it up in
// the log. Same ID, completely different information at each end.
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
 * Sessions stored in Postgres (connect-pg-simple) rather than memory —
 * in-memory sessions disappear on restart, which logs everyone out and
 * makes proper invalidation impossible.
 *
 * Cookie flags: HttpOnly means JS can't read it (XSS can't steal the
 * session), Secure keeps it off plain HTTP, SameSite=strict tells the
 * browser not to attach it to cross-site requests at all (extra layer
 * on top of our CSRF token check). maxAge 24h means a stolen cookie
 * at least expires — it's not valid indefinitely.
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

// Global error handler — must be registered last, after all routes,
// and must have exactly 4 params (err, req, res, next) for Express
// to treat it as an error handler rather than normal middleware.
//
// Without this, Express's default would send the full stack trace back
// to the client — file paths, library versions, sometimes DB column names.
// Instead: known client errors get a sensible 4xx, everything else gets a
// generic 500 + the requestId. The full trace is logged server-side with
// that same ID so we can pull it from the log when a user reports an error.
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