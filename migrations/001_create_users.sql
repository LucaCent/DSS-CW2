-- 001_create_users.sql
-- Users table schema. recovery_email and profile_bio are stored as BYTEA
-- because they hold AES-256-GCM ciphertext produced by utils/encryption.js
-- (hex-encoded string: iv:authTag:ciphertext).
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
    password_hash   TEXT NOT NULL,           -- owned by Argon2id card (Luca)
    recovery_email  TEXT,                    -- AES-256-GCM encrypted
    profile_bio     TEXT,                    -- AES-256-GCM encrypted
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
    password_hash   TEXT NOT NULL,
    recovery_email  TEXT,
    profile_bio     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
