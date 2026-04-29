# Secure Blog Application

A secure, full-featured blog application built with Node.js, Express.js, and PostgreSQL. Designed to demonstrate comprehensive web security mitigations including protection against SQL injection, XSS, CSRF, session hijacking, account enumeration, and more.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| **Node.js** | v18.x or later |
| **PostgreSQL** | v14.x or later |
| **npm** | v9.x or later |
| **Authenticator app** | Google Authenticator, Authy, or any TOTP-compatible app |

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd DSS-CW2
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
```bash
cp .env.example .env
```
Edit `.env` with your PostgreSQL credentials and generate strong secrets:
- `DB_USER` / `DB_PASS` / `DB_NAME` — your PostgreSQL connection details
- `SESSION_SECRET` — a long random string (min 64 chars)
- `PEPPER` — a secret string for password peppering (min 32 chars)
- `ENCRYPTION_KEY` — exactly 64 hex characters (32 bytes for AES-256)
- `CSRF_SECRET` — a random string for CSRF token generation

> **Important:** Never commit the `.env` file to version control.

### 4. Create the PostgreSQL Database
```bash
# Connect to PostgreSQL
psql -U your_username

# Create the database
CREATE DATABASE secure_blog;

# Connect to the new database
\c secure_blog

# Run the schema
\i db/schema.sql

# Exit
\q
```

Or in one command:
```bash
psql -U your_username -d secure_blog -f db/schema.sql
```

### 5. Start the Application
```bash
npm start
```
The application will be available at **http://localhost:3000**

### 6. Run Unit Tests
```bash
npm test
```

### 7. Run npm Audit
```bash
npm audit
```
This checks all dependencies for known security vulnerabilities. Fix any critical or high severity issues with:
```bash
npm audit fix
```

---

## Project Structure

```
/
├── server.js                  Entry point — middleware + route wiring
├── .env                       Environment variables (never commit)
├── .env.example               Template with placeholder values
├── README.md                  This file
├── package.json               Dependencies and scripts
├── /routes
│   ├── auth.js                Register, login, logout, 2FA
│   ├── posts.js               CRUD + search for blog posts
│   └── passwordReset.js       Secure password reset flow
├── /middleware
│   ├── sessionCheck.js        Auth guard with idle + absolute timeout
│   ├── csrfMiddleware.js      CSRF token generation + validation
│   └── rateLimiter.js         IP-based rate limiting
├── /db
│   ├── pool.js                PostgreSQL connection pool
│   └── schema.sql             All CREATE TABLE statements
├── /utils
│   ├── crypto.js              AES-256 encryption/decryption helpers
│   ├── sanitise.js            Input validation + HTML encoding
│   ├── totp.js                TOTP 2FA helpers (generate, verify, QR)
│   └── logger.js              Security event logging (winston)
├── /public
│   ├── index.html             Single-page HTML application
│   ├── /css/style.css         Stylesheet
│   └── /js/app.js             Client-side logic
├── /logs
│   └── security.log           Auto-generated security event log
└── /tests
    ├── /unit
    │   ├── password.test.js   Password hashing tests
    │   ├── csrf.test.js       CSRF token tests
    │   ├── sanitise.test.js   Input sanitisation tests
    │   ├── totp.test.js       TOTP validation tests
    │   └── session.test.js    Session expiry tests
    ├── security-test-plan.md  Manual security test cases
    └── think-aloud-plan.md    Usability test plan
```

---

## Security Mitigations Implemented

### 1. Account Enumeration Prevention
- Identical generic error messages for wrong username vs wrong password
- Artificial 200ms delay on all login responses to prevent timing attacks
- Account lockout after 5 failed attempts (15-minute lockout period)
- IP-based rate limiting on auth routes (10 attempts per 15 minutes)

### 2. Session Hijacking Prevention
- Session cookies set with `HttpOnly`, `Secure` (in production), and `SameSite=Strict`
- Session ID regenerated on every successful login
- Idle timeout: 15 minutes of inactivity
- Absolute session expiry: 24 hours
- Server-side session validation on every protected route
- Sessions stored in PostgreSQL (not in-memory)

### 3. SQL Injection Prevention
- Every database query uses parameterised statements (`$1`, `$2`, etc.)
- No string concatenation of user input into SQL anywhere
- Server-side input validation on all fields (type, length, format)

### 4. Cross-Site Scripting (XSS) Prevention
- All user-supplied content HTML-encoded before rendering (using `he` library)
- Content Security Policy (CSP) header restricts script sources to `'self'` only
- No inline scripts allowed

### 5. Cross-Site Request Forgery (CSRF) Prevention
- Unique per-session CSRF token generated using `crypto.randomBytes()`
- Token embedded in all forms and sent as `x-csrf-token` header
- Token validated server-side on every POST, PUT, DELETE request
- Timing-safe comparison to prevent token timing attacks
- Combined with `SameSite=Strict` cookies for defence in depth

### 6. Password Hashing, Salting & Peppering
- Passwords hashed using bcrypt with 12 rounds
- Unique per-user salt (automatic in bcrypt)
- Server-side pepper from environment variable appended before hashing

### 7. Database Encryption
- Email addresses encrypted with AES-256-CBC at the application layer
- TOTP secrets encrypted before database storage
- Encryption key stored in `.env` file, never hardcoded
- Random IV per encryption operation

### 8. TOTP Two-Factor Authentication
- TOTP secret generated on registration with QR code
- 6-digit code required on every login (after password)
- Uses `otplib` library (RFC 6238 compliant)
- TOTP secrets stored encrypted in the database

### 9. Additional Security Hardening
- **Helmet.js security headers**: X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy
- **Clickjacking protection**: CSP `frame-ancestors 'none'` + `X-Frame-Options: DENY`
- **IDOR prevention**: Ownership verification on all edit/delete operations
- **Input length limits**: Server-side enforcement on all fields
- **Secure password reset**: One-time token, hashed storage, 15-minute expiry
- **Security logging**: Failed logins, CSRF failures, IDOR attempts logged with timestamp and IP
- **Generic error messages**: No stack traces or SQL errors exposed to clients
- **Unhandled rejection handler**: Prevents process crashes from async errors

---

## Usage Guide

### Registration
1. Click **Register** in the navigation
2. Enter a username (3–50 chars, alphanumeric + underscores), email, and password (min 8 chars with uppercase, lowercase, number, and special character)
3. After registration, scan the QR code with your authenticator app
4. Enter the 6-digit code to verify and enable 2FA

### Login
1. Click **Login** and enter your credentials
2. If 2FA is enabled, enter the 6-digit code from your authenticator app
3. You will be redirected to the homepage

### Blog Posts
- **Create**: Click "New Post" to write and publish
- **Edit/Delete**: Go to "My Posts" to manage your own posts
- **Search**: Use the search feature to find posts by keyword

### Password Reset
1. Click "Forgot password?" on the login page
2. Enter your username to receive a reset token
3. Enter the token and your new password to complete the reset

---

## License
This project was created for the DSS coursework assessment.
