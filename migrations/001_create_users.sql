-- 001_create_users.sql
-- NOTE: The full schema (sessions, posts, password_reset_tokens, security_logs)
-- lives in db/schema.sql. Run that file to initialise a fresh database:
--   psql -U postgres -h localhost -d dss_blog -f db/schema.sql
--
-- password_hash:          Argon2id output. TEXT rather than VARCHAR to avoid
--                         length surprises if OWASP params change.
-- email_encrypted:        AES-256-GCM ciphertext produced by utils/crypto.js
--                         (hex-encoded string: iv:authTag:ciphertext).
-- totp_secret_encrypted:  AES-256-GCM ciphertext of the TOTP base32 secret.

CREATE TABLE IF NOT EXISTS users (
    id                      SERIAL PRIMARY KEY,
    username                VARCHAR(50) UNIQUE NOT NULL,
    email_encrypted         TEXT NOT NULL,
    password_hash           TEXT NOT NULL,
    totp_secret_encrypted   TEXT,
    totp_enabled            BOOLEAN DEFAULT FALSE,
    failed_login_attempts   INTEGER DEFAULT 0,
    locked_until            TIMESTAMP,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
