/**
 * SECURITY: Server-Side Security Logger
 * Attack prevented: Undetected intrusion, forensic blindness
 * How it works: Logs suspicious activity (repeated failed logins, CSRF
 *   failures, unexpected input patterns) to both a file and the console
 *   with timestamps and IP addresses. This creates an audit trail for
 *   incident response and forensic analysis.
 *
 * Library used: winston (v3.x) — the most widely used logging library
 *   for Node.js, supporting multiple transports (file, console) and
 *   structured log formatting.
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

/**
 * Log a security-related event.
 * @param {string} message - Description of the event
 * @param {Object} meta - Additional context (ip, username, etc.)
 */
function security(message, meta = {}) {
  logger.warn(`[SECURITY] ${message}`, meta);
}

/**
 * Log a general info event.
 */
function info(message, meta = {}) {
  logger.info(message, meta);
}

module.exports = { security, info };
