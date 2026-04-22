require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const https = require('https');
const fs = require('fs');
const db = require('./db');

const app = express();

// ── Body parsing ──────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static files (the frontend template) ─────────────────
app.use(express.static(path.join(__dirname, 'food blog')));

// ── Session middleware (MUST come before CSRF) ────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,           // HTTPS now active — cookies only sent over TLS
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60  // 1 hour
  }
}));

// ── Routes will be added here by the team ─────────────────
// app.use('/auth', require('./routes/auth'));
// app.use('/posts', require('./routes/posts'));

// ── Global error handler (prevents stack trace leakage) ───
app.use((err, req, res, next) => {
  console.error(err.stack);   // logs full error server-side only
  res.status(500).json({ error: 'Something went wrong' });
});

// ── HTTPS server startup ──────────────────────────────────
// Uses a self-signed cert for local dev. key.pem and cert.pem are
// gitignored — each developer generates their own via openssl.
const httpsOptions = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

const PORT = 3000;
https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Server running at https://localhost:${PORT}`);
});