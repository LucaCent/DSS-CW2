/*
 * Database connection pool using pg (node-postgres).
 *
 * SECURITY: SQL Injection Prevention
 * Attack prevented: SQL injection
 * How it works: Every query that goes through this pool must use
 *   parameterised statements ($1, $2, ...) instead of concatenating
 *   user input into the SQL string. pg treats parameter values as
 *   pure data, so they can never be interpreted as SQL commands.
 *   The pool also caps concurrent connections at 20 to avoid
 *   resource exhaustion if traffic spikes.
 */

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client:', err.message);
});

module.exports = pool;
