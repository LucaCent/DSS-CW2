/**
 * Unit Tests — CSRF Token Generation and Validation
 * Tests the custom CSRF middleware logic.
 */

const crypto = require('crypto');

// Replicate the CSRF functions from the middleware
function generateCSRFToken(session) {
  const token = crypto.randomBytes(32).toString('hex');
  session.csrfToken = token;
  return token;
}

function validateCSRFToken(submittedToken, sessionToken) {
  if (!submittedToken || !sessionToken) return false;

  try {
    const tokenBuffer = Buffer.from(submittedToken, 'hex');
    const sessionBuffer = Buffer.from(sessionToken, 'hex');

    if (tokenBuffer.length !== sessionBuffer.length) return false;
    return crypto.timingSafeEqual(tokenBuffer, sessionBuffer);
  } catch (err) {
    return false;
  }
}

describe('CSRF Token Generation and Validation', () => {
  test('should generate a 64-character hex token', () => {
    const session = {};
    const token = generateCSRFToken(session);
    expect(token).toBeDefined();
    expect(token.length).toBe(64); // 32 bytes = 64 hex chars
    expect(/^[0-9a-f]+$/.test(token)).toBe(true);
  });

  test('should store the token in the session', () => {
    const session = {};
    const token = generateCSRFToken(session);
    expect(session.csrfToken).toBe(token);
  });

  test('should generate unique tokens on each call', () => {
    const session1 = {};
    const session2 = {};
    const token1 = generateCSRFToken(session1);
    const token2 = generateCSRFToken(session2);
    expect(token1).not.toBe(token2);
  });

  test('should validate a correct token', () => {
    const session = {};
    const token = generateCSRFToken(session);
    expect(validateCSRFToken(token, session.csrfToken)).toBe(true);
  });

  test('should reject a mismatched token', () => {
    const session = {};
    generateCSRFToken(session);
    const fakeToken = crypto.randomBytes(32).toString('hex');
    expect(validateCSRFToken(fakeToken, session.csrfToken)).toBe(false);
  });

  test('should reject a null submitted token', () => {
    const session = {};
    generateCSRFToken(session);
    expect(validateCSRFToken(null, session.csrfToken)).toBe(false);
  });

  test('should reject a null session token', () => {
    const token = crypto.randomBytes(32).toString('hex');
    expect(validateCSRFToken(token, null)).toBe(false);
  });

  test('should reject an empty string token', () => {
    const session = {};
    generateCSRFToken(session);
    expect(validateCSRFToken('', session.csrfToken)).toBe(false);
  });

  test('should reject tokens of different lengths', () => {
    const session = {};
    generateCSRFToken(session);
    const shortToken = crypto.randomBytes(16).toString('hex');
    expect(validateCSRFToken(shortToken, session.csrfToken)).toBe(false);
  });
});
