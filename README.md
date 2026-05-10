# The Survivor Network — DSS Coursework (Group 15)

A cancer survivor community blog built for the CMP-6045B Digital Systems Security coursework. The point was to actually implement the security controls rather than just describe them — everything below is wired up and testable.

Built with Node.js, Express, and PostgreSQL.

---

## Prerequisites

- Node.js v18+
- PostgreSQL v14+
- An authenticator app (Google Authenticator, Authy, or anything TOTP-compatible)

---

## Getting it running

**1. Clone and install**
```bash
git clone https://github.com/LucaCent/DSS-CW2.git
cd DSS-CW2
npm install
```

**2. Create the `.env` file**

Create a file called `.env` in the project root with the following variables:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_postgres_user
DB_PASS=your_postgres_password
DB_NAME=dss_cw2
SESSION_SECRET=some_long_random_string_64_chars_or_more
PEPPER=a_secret_string_appended_to_passwords_before_hashing
ENCRYPTION_KEY=a64characterhexstringexactly64charswhichdecodesto32bytes00000000
```

Notes on the values:
- `SESSION_SECRET` — any long random string, not stored in DB
- `PEPPER` — secret appended to every password before hashing; never stored in DB
- `ENCRYPTION_KEY` — must be **exactly 64 hex characters** (decoded to 32 bytes for AES-256). Generate one with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

`.env` is in `.gitignore` and will not be committed.

**3. Create the database and run the schema**
```bash
psql -U your_username -c "CREATE DATABASE dss_cw2;"
psql -U your_username -d dss_cw2 -f db/schema.sql
```

**4. Generate TLS certs for HTTPS (optional but recommended)**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Without certs the server falls back to plain HTTP. With them you get HTTPS and the Secure cookie / HSTS headers kick in properly. The cert files are excluded from git.

**5. Start the server**
```bash
npm start
```

Runs at `https://localhost:3000` (or `http://localhost:3000` without certs).

---

## Tests

```bash
npm test                     # 73 Jest unit tests across 8 suites
npm audit                    # dependency CVE scan
bash tests/stress-test.sh    # HTTP-level security checks (needs server running)
```

---

## Project layout

```
├── server.js                  Entry point — middleware stack order matters
├── routes/
│   ├── auth.js                Register, login, logout, 2FA setup
│   ├── posts.js               CRUD + search (IDOR ownership check on edit/delete)
│   └── passwordReset.js       Token-based password reset
├── middleware/
│   ├── csrfMiddleware.js      Custom CSRF token generation and validation
│   ├── rateLimiter.js         IP-based rate limiter (plain Map, no library)
│   └── sessionCheck.js        Auth guard, idle timeout, absolute timeout
├── utils/
│   ├── crypto.js              AES-256-GCM encrypt/decrypt + reset token hashing
│   ├── hashing.js             Argon2id hash + verify (pepper applied here)
│   ├── sanitise.js            Input length checks and HTML output encoding
│   ├── totp.js                TOTP secret generation, QR code, verification
│   └── logger.js              Appends security events to logs/security.log
├── db/
│   ├── pool.js                Postgres connection pool (max 20)
│   └── schema.sql             Table definitions
├── public/                    Single-page frontend (HTML + JS + CSS)
├── tests/
│   ├── unit/                  Jest test suites (8 files)
│   ├── stress-test.sh         Automated HTTP security probes
│   └── DSS-CW2-Test-Plan.docx Manual test plan and evidence
└── logs/
    └── security.log           Written at runtime, not committed
```

---

## Security controls

### Password storage
Argon2id with a per-user salt plus a server-side pepper. Argon2id won the 2015 Password Hashing Competition and is the current OWASP recommendation. It's memory-hard (64 MB per attempt), which is what makes GPU cracking impractical — bcrypt doesn't have this. The pepper means a stolen database dump still isn't enough to start cracking without also having the server environment.

### Encryption at rest
Emails and TOTP secrets are encrypted with AES-256-GCM before being stored. GCM mode gives authenticated encryption — the auth tag lets you detect any tampering with the ciphertext before decryption even starts, which CBC doesn't. A fresh random IV per call means the same plaintext never produces the same ciphertext. Stored format: `iv_hex:authTag_hex:ciphertext_hex`.

### CSRF protection
Custom implementation — no library. A 32-byte random token is generated per session and required on every POST/PUT/DELETE request, either as an `x-csrf-token` header or `_csrf` body field. Validation uses `crypto.timingSafeEqual` to avoid timing leaks. Combined with `SameSite=Strict` cookies.

### Session security
Sessions are stored in Postgres via `connect-pg-simple`, not in memory. Cookie flags: `HttpOnly`, `Secure` (when HTTPS is available), `SameSite=Strict`. Session ID is regenerated on login to prevent fixation. Two timeouts run server-side: 15-minute idle, 24-hour absolute.

### Account enumeration prevention
Login always returns `"Invalid credentials"` regardless of whether the username exists or the password is wrong. A dummy Argon2 hash runs when the user isn't found so the response time doesn't give anything away. A 200ms minimum delay is enforced on all login responses. Accounts lock after 5 failed attempts for 15 minutes.

### SQL injection
All queries use parameterised statements (`$1`, `$2`, ...) throughout. No user input is ever concatenated into a SQL string.

### XSS
All user-supplied content is HTML-encoded in API responses through a custom `encodeHTML()` function (`&`, `<`, `>`, `"`, `'` all escaped). The CSP header restricts scripts to `'self'`, so injected `<script>` tags are blocked at the browser level anyway.

### Security headers
Set by Helmet: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` (1 year), `Referrer-Policy: same-origin`, `Permissions-Policy` (camera/mic/geolocation all denied), `frame-ancestors: 'none'`.

### IDOR prevention
Before any edit or delete, the post's `user_id` is fetched from the database and compared against `req.session.userId`. Mismatches get a 403 and are logged. Without this check, changing the post ID in a request would let anyone modify anyone else's content.

### Rate limiting
Two in-memory limiters using a plain `Map` — no library: 100 req/15 min site-wide, 10 req/15 min on auth endpoints. Separate from the per-account lockout, which covers a different attack shape.

### Password reset
A 32-byte random token from `crypto.randomBytes()`. Only the SHA-256 hash is stored — the raw token is never in the database. Expires after 15 minutes, single-use, and a new request invalidates any existing token. The raw token is returned in the API response for demo purposes (would be emailed in a real deployment).

### Error handling
The global error handler sends only a generic message and a random `requestId` to the client. The full error with stack trace is logged server-side under the same ID. No file paths, query details, or stack frames reach the response.

---

## Known limitations

- Password reset tokens are returned in the API response instead of being emailed — email is out of scope for the coursework.
- The CSP allows `unsafe-inline` for script attributes because the frontend uses inline `onclick`/`onsubmit`. Removing this would mean refactoring the frontend to use `addEventListener` throughout.
- Rate limiter state lives in memory and resets on server restart. Production would need a shared store like Redis.
