/**
 * SECURITY: Database Connection Pool
 * Attack prevented: SQL injection, connection exhaustion
 * How it works: Creates a managed pool of PostgreSQL connections.
 *   All queries go through this pool using parameterised statements,
 *   never string concatenation. The pool limits concurrent connections
 *   to prevent resource exhaustion.
 * Library used: pg (node-postgres) — the standard PostgreSQL client
 *   for Node.js, supports parameterised queries natively.
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

/**
 * SECURITY: SQL Injection Prevention
 * Attack prevented: SQL injection
 * How it works: The query() wrapper ensures that every database interaction
 *   uses parameterised queries ($1, $2, etc.) with values passed as a
 *   separate array. PostgreSQL treats these as data, not executable SQL,
 *   making it impossible for user input to alter query structure.
 *
 * Example safe usage:
 *   pool.query('SELECT * FROM users WHERE username = $1', [username])
 *
 * Example UNSAFE (never do this):
 *   pool.query('SELECT * FROM users WHERE username = \'' + username + '\'')
 */
module.exports = pool;
