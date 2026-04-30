/*
 * SECURITY: Security Event Logging
 * Attack prevented: Undetected intrusions / lack of audit trail
 * How it works: Suspicious events (failed logins, CSRF failures, IDOR
 *   attempts) are written to logs/security.log with a timestamp and the
 *   source IP. If something goes wrong we have a paper trail to look at.
 *
 * Uses winston (v3) for file + console logging with rotation.
 */

const winston = require('winston');
const path = require('path');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
      return `[${timestamp}] ${level.toUpperCase()}: ${message}${metaStr}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, '..', 'logs', 'security.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.Console(),
  ],
});

function security(message, meta = {}) {
  logger.warn(`[SECURITY] ${message}`, meta);
}

function info(message, meta = {}) {
  logger.info(message, meta);
}

module.exports = { security, info };
