-- Migration 002: add auth_method and recovery_codes to existing users tables.
-- Run this if you already have the database from schema.sql v1.
-- Safe to run multiple times (IF NOT EXISTS / idempotent ALTER).

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS auth_method VARCHAR(10) DEFAULT 'totp' NOT NULL,
  ADD COLUMN IF NOT EXISTS recovery_codes TEXT;
