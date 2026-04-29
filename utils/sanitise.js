/**
 * SECURITY: Input Sanitisation and Output Encoding
 * Attack prevented: Cross-Site Scripting (XSS) — both stored and reflected
 *
 * Stored XSS: An attacker injects malicious script into data that is saved
 *   in the database (e.g. a blog post body). When other users view that
 *   content, the script executes in their browser, potentially stealing
 *   cookies or session tokens.
 *
 * Reflected XSS: An attacker crafts a URL containing malicious script in
 *   a query parameter (e.g. a search term). If the server reflects that
 *   input back into the page without encoding, the script executes in
 *   the victim's browser when they click the link.
 *
 * How this module prevents XSS:
 *   1. HTML encoding: All user-supplied input is passed through the `he`
 *      library's encode() function before being rendered in any page.
 *      This converts characters like <, >, &, ", ' into their HTML
 *      entity equivalents (&lt;, &gt;, &amp;, etc.), making them inert.
 *   2. Input validation: Fields are validated for type, length, and format
 *      before processing, rejecting obviously malicious input early.
 *
 * Library used: he (v1.2.0) — a robust, well-tested HTML entity encoder/
 *   decoder. Chosen because it handles all edge cases and is widely used.
 */

const he = require('he');

/**
 * HTML-encode a string to prevent XSS when rendered in a page.
 * Converts <, >, &, ", ' and other special characters to HTML entities.
 */
function encodeHTML(input) {
  if (typeof input !== 'string') return '';
  return he.encode(input, { useNamedReferences: true });
}

/**
 * SECURITY: Input Length Limits
 * Attack prevented: Buffer overflow, denial of service, database overflow
 * How it works: Enforces maximum length on all user-supplied fields
 *   server-side. Even if client-side validation is bypassed, the server
 *   rejects oversized input.
 */
const INPUT_LIMITS = {
  username: { min: 3, max: 50 },
  password: { min: 8, max: 128 },
  email: { min: 5, max: 254 },
  postTitle: { min: 1, max: 200 },
  postContent: { min: 1, max: 5000 },
  searchQuery: { min: 1, max: 200 },
  totpCode: { exact: 6 },
};

/**
 * Validate a field's length against defined limits.
 * Returns { valid: boolean, message: string }
 */
function validateLength(field, value) {
  const limits = INPUT_LIMITS[field];
  if (!limits) return { valid: true, message: '' };

  if (typeof value !== 'string') {
    return { valid: false, message: `${field} must be a string` };
  }

  if (limits.exact && value.length !== limits.exact) {
    return { valid: false, message: `${field} must be exactly ${limits.exact} characters` };
  }

  if (limits.min && value.length < limits.min) {
    return { valid: false, message: `${field} must be at least ${limits.min} characters` };
  }

  if (limits.max && value.length > limits.max) {
    return { valid: false, message: `${field} must be at most ${limits.max} characters` };
  }

  return { valid: true, message: '' };
}

/**
 * Validate username format: alphanumeric and underscores only.
 */
function validateUsername(username) {
  const lengthCheck = validateLength('username', username);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, message: 'Username may only contain letters, numbers, and underscores' };
  }
  return { valid: true, message: '' };
}

/**
 * Validate email format (basic check).
 */
function validateEmail(email) {
  const lengthCheck = validateLength('email', email);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { valid: false, message: 'Invalid email format' };
  }
  return { valid: true, message: '' };
}

/**
 * Validate password strength.
 */
function validatePassword(password) {
  const lengthCheck = validateLength('password', password);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  return { valid: true, message: '' };
}

module.exports = {
  encodeHTML,
  validateLength,
  validateUsername,
  validateEmail,
  validatePassword,
  INPUT_LIMITS,
};
