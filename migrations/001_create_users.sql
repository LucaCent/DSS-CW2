-- 001_create_users.sql
-- Users table schema.
--
-- password_hash:   Argon2id output (~97 chars). TEXT rather than
--                  VARCHAR to avoid length surprises if OWASP params change.
-- recovery_email:  AES-256-GCM ciphertext produced by utils/encryption.js
--                  (hex-encoded string: iv:authTag:ciphertext).
-- profile_bio:     same — encrypted at rest.

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    recovery_email  TEXT,
    profile_bio     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
