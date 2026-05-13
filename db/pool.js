/*
 * PostgreSQL connection pool (node-postgres).
 * Capped at 20 connections — if traffic spikes, queries queue rather than
 * hammering the DB with unlimited parallel clients.
 *
 * SQL injection: every query using this pool should use $1/$2/... parameters.
 * pg sends those as typed values, never as part of the SQL string, so there's
 * no way for user input to be interpreted as a SQL command. We went through
 * all the routes to make sure nothing concatenates user input into a query.
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
