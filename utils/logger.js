/*
 * SECURITY: Security Event Logging
 * Attack prevented: Undetected intrusions / lack of audit trail
 * How it works: Suspicious events (failed logins, CSRF failures, IDOR
 *   attempts) are written to logs/security.log with a timestamp and the
 *   source IP. If something goes wrong we have a paper trail to look at.
 *
 * Implemented with Node's built-in fs.appendFileSync — no library needed.
 */

const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '..', 'logs', 'security.log');

// Make sure the logs directory exists before we try to write to it
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

function formatTimestamp() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function writeLine(level, message, meta) {
  const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
  const line = `[${formatTimestamp()}] ${level}: ${message}${metaStr}\n`;
  console.log(line.trim());
  fs.appendFileSync(LOG_FILE, line, 'utf8');
}

function security(message, meta = {}) {
  writeLine('[SECURITY]', message, meta);
}

function info(message, meta = {}) {
  writeLine('INFO', message, meta);
}

module.exports = { security, info };
