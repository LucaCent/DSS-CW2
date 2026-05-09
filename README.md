# The Survivor Network — DSS Coursework (Group 15)

A blog application built for the CMP-6045B Digital Systems Security coursework. The focus is on implementing real security controls rather than just describing them — everything listed below is actually wired up and testable.

Built with Node.js, Express, and PostgreSQL.

---

## What you need before starting

- Node.js v18+
- PostgreSQL v14+
- An authenticator app (Google Authenticator, Authy, anything TOTP-compatible)

---

## Getting it running

**1. Clone and install**
```bash
git clone https://github.com/LucaCent/DSS-CW2.git
cd DSS-CW2
npm install
```

**2. Set up the environment file**
```bash
cp .env.example .env
```

Open `.env` and fill in:
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` — your Postgres connection
- `SESSION_SECRET` — long random string, 64+ chars
- `PEPPER` — secret appended to passwords before hashing, 32+ chars
- `ENCRYPTION_KEY` — exactly 32 ASCII characters (used as AES-256 key)

Don't commit `.env`. It's in `.gitignore` already.

**3. Create the database and run the schema**
```bash
psql -U your_username -c "CREATE DATABASE dss_cw2;"
psql -U your_username -d dss_cw2 -f db/schema.sql
```

**4. Generate TLS certs for HTTPS (optional but recommended)**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Without certs the server falls back to plain HTTP on localhost. With them you get HTTPS and the HSTS/Secure cookie features work properly.

**5. Start the server**
```bash
npm start
```

Runs at `https://localhost:3000` (or `http://` if no certs).

---

## Running the tests

```bash
npm test          # Jest unit tests (73 tests across 8 suites)
npm audit         # Check dependencies for known CVEs
bash tests/stress-test.sh   # HTTP-level security checks (run with server up)
```

---

## Project layout

```
├── server.js                 Entry point — middleware order matters here
├── /routes
│   ├── auth.js               Register, login, logout, 2FA
│   ├── posts.js              CRUD + search (IDOR checks on edit/delete)
│   └── passwordReset.js      Token-based reset flow
├── /middleware
│   ├── csrfMiddleware.js     CSRF token generation + validation
│   ├── rateLimiter.js        IP-based rate limiting (Map-based, no library)
│   └── sessionCheck.js       Auth guard + idle/absolute timeout enforcement
├── /utils
│   ├── crypto.js             AES-256-GCM encrypt/decrypt + token hashing
│   ├── hashing.js            Argon2id hash + verify (with pepper)
│   ├── sanitise.js           Input validation and HTML encoding
│   ├── totp.js               TOTP secret generation, QR code, verification
│   └── logger.js             Security event log (logs/security.log)
├── /db
│   ├── pool.js               Postgres connection pool (capped at 20)
│   └── schema.sql            Table definitions
├── /public                   Frontend (single HTML page + JS + CSS)
├── /tests
│   ├── /unit                 Jest test suites
│   ├── stress-test.sh        Automated HTTP security checks
│   └── DSS-CW2-Test-Plan.docx  Manual test plan + evidence
└── /logs
    └── security.log          Written at runtime, not committed
```

---

## Security controls

### Password storage
Argon2id with a per-user salt (embedded in the hash output automatically) plus a server-side pepper from `.env`. Argon2id won the 2015 Password Hashing Competition and is the current OWASP recommendation — it's memory-hard (64 MB per attempt), which makes GPU cracking expensive. Even a full database dump is useless without the pepper.

### Encryption at rest
Email addresses and TOTP secrets are encrypted with AES-256-GCM before going into the database. GCM gives authenticated encryption — the auth tag means tampered ciphertext is detected before decryption. A fresh random IV is generated per encryption call so the same plaintext never produces the same ciphertext. Format stored: `iv_hex:authTag_hex:ciphertext_hex`.

### CSRF protection
Custom implementation: 32-byte random token stored in the session, required on every POST/PUT/DELETE as `x-csrf-token` header or `_csrf` body field. Comparison uses `crypto.timingSafeEqual` to prevent byte-by-byte timing attacks. Combined with `SameSite=Strict` cookies.

### Session security
Sessions stored in Postgres (not memory) via `connect-pg-simple`. Cookie flags: `HttpOnly` (no JS access), `Secure` (HTTPS only), `SameSite=Strict`. Session ID regenerated on login to prevent fixation. Two timeouts enforced server-side: 15-minute idle and 24-hour absolute.

### Account enumeration prevention
Login always returns `"Invalid credentials"` regardless of whether the username exists or the password is wrong. When the user doesn't exist, a dummy Argon2 hash runs anyway to equalise timing. A 200ms floor is applied to all login responses. Account locks after 5 failures for 15 minutes.

### SQL injection
Every query uses parameterised statements (`$1`, `$2`, ...). No user input is concatenated into SQL strings anywhere. Checked across all routes.

### XSS
All user content is HTML-encoded before being sent in API responses using a custom `encodeHTML()` function (`&`, `<`, `>`, `"`, `'` all escaped). CSP header restricts scripts to `'self'` only — injected `<script>` tags are blocked.

### Security headers (Helmet)
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` (1 year), `Referrer-Policy: same-origin`, `Permissions-Policy` (camera/mic/geo denied), CSP `frame-ancestors: 'none'`.

### IDOR prevention
Edit and delete routes fetch the post's `user_id` from the database before making any changes and compare it against `req.session.userId`. Mismatches return 403 and get logged.

### Rate limiting
Two limiters built with a plain `Map` (no library): 100 req/15 min site-wide, 10 req/15 min on auth routes. The IP limiter and per-account lockout cover different attack shapes.

### Password reset
Random 32-byte token generated with `crypto.randomBytes()`. Only the SHA-256 hash is stored in the database. Token expires in 15 minutes, is single-use, and requesting a new one invalidates any outstanding tokens. (Token is returned in the API response for demo purposes — would be emailed in production.)

### Error handling
Global error handler returns only a generic message and a random `requestId` to the client. Full stack traces are logged server-side tagged with the same ID. No file paths, library versions, or database details leak to the response.

---

## Known limitations

- Password reset token is returned in the API response rather than sent by email (email sending is out of scope for the coursework).
- `scriptSrcAttr` in the CSP still allows `unsafe-inline` because the frontend uses `onclick`/`onsubmit` attributes. Fixing this would require refactoring the frontend to use `addEventListener()`.
- Rate limiter state is in-memory and resets on server restart. A Redis-backed limiter would be needed in production.
