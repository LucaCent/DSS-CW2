// ── CSRF IMPLEMENTATION NOTE FOR TEAMMATES ────────────────
// All non-GET fetch requests (POST, PUT, DELETE) MUST include
// the CSRF token in the header, otherwise the request will be
// rejected with a 403 error.
//
// Example of how to include it in a fetch request:
//
// const { csrfToken } = await fetch('/csrf-token').then(r => r.json());
//
// fetch('/your-route', {
//   method: 'POST',
//   headers: {
//     'Content-Type': 'application/json',
//     'x-csrf-token': csrfToken
//   },
//   body: JSON.stringify({ ... })
// });
// ─────────────────────────────────────────────────────────
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { doubleCsrf } = require('csrf-csrf');
const path = require('path');
const db = require('./db');

const app = express();

// ── 1. Helmet (security headers, must be first) ───────────
app.use(helmet());

// ── 2. Rate limiting (before routes, limits brute force) ──
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // max 100 requests per window
  message: { error: 'Too many requests, please try again later' }
});
app.use(limiter);

// ── 3. Body parsing (before CSRF reads req.body) ─────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── 4. Static files ───────────────────────────────────────
app.use(express.static(path.join(__dirname, 'food blog')));

// ── 5. Session (MUST come before CSRF) ───────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,   // change to true once HTTPS is set up
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60  // 1 hour
  }
}));

// ── 6. CSRF protection (MUST come after session) ─────────
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,   // change to true once HTTPS is set up
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});
app.use(doubleCsrfProtection);

// ── 7. CSRF token endpoint (frontend fetches this) ────────
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: generateToken(req, res) });
});

// ── 8. Routes (added here by the team) ───────────────────
// app.use('/auth', require('./routes/auth'));
// app.use('/posts', require('./routes/posts'));

// ── 9. Global error handler ───────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong' });
});

// ── Start server ──────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});